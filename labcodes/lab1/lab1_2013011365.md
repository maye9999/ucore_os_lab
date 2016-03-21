# Lab1 Report
#### 计34 马也 2013011365
---

## 练习一
### 第一题

> 操作系统镜像文件ucore.img是如何一步一步生成的？(需要比较详细地解释Makefile中每一条相关命令和命令参数的含义，以及说明命令导致的结果)

根据Makefile可得的 `UCOREIMG` 的前驱项为 `kernel` 和 `bootblock`。

```
$(UCOREIMG): $(kernel) $(bootblock)
	$(V)dd if=/dev/zero of=$@ count=10000
	$(V)dd if=$(bootblock) of=$@ conv=notrunc
	$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc
```

首先生成 `kernel` ，其前驱项为 `kernel.ld` 和 `KOBJS` ，即链接的脚本(ld文件)以及内核代码编译得到的.o文件。其中 `kernel.ld` 规定了链接时的格式以及代码段数据段等内容的位置，链接器则根据该文件链接生成的所有.o文件。这些.o文件包括 init.o readline.o stdio.o kdebug.o kmonitor.o panic.o clock.o console.o intr.o picirq.o trap.o trapentry.o vectors.o pmm.o printmt.o string.o，他们均由对应.c文件直接编译得到。编译过程的参数由 `KCFLAGS`变量指定。

```
$(kernel): tools/kernel.ld
$(kernel): $(KOBJS)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)
```

生成得到这些.o文件之后，进行链接操作，其语句为 `$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)` ，意思是将刚刚得到的所有.o文件都连接起来，遵循ld文件规定的格式和 `LDFLAGS` 规定的一些属性，最终得到 `kernel` 。

接着生成 `bootblock`，其需要sign文件和两个.o文件bootasm.o bootmain.o。其中sign文件由 tools/sign.c直接编译得到，而.o文件则分别由bootasm.S和bootmain.c编译得到，编译参数由 `CFLAGS` 定义。

```
$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
	@$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
	@$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
	@$(call totarget,sign) $(call outfile,bootblock) $(bootblock)
```

得到这三个文件之后，和 `kernel` 类似，调用链接器将两个.o文件链接生成 bootblock.o，再使用objcopy将其拷贝到bootblock.out文件中，最后使用sign工具处理，得到最终的 `bootblock`。

最后的最后，在得到了 `kernel` 和 `bootblock` 之后，执行以下三个语句

```
dd if=/dev/zero of=bin/ucore.img count=10000
dd if=bin/bootblock of=bin/ucore.img conv=notrunc
dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
```

分别代表的意义是：拷贝10000个块的0到ucore.img文件中；把bootblock写入ucore.img的第一个块中；把kernel写入ucore.img的第二个块中（可能更大）。最终，得到了系统镜像 `ucore.img`。

在阅读Makefile的过程中，遇到了以下困惑，最终通过网上查阅资料得以解决，其中包括：

* `$(call totarget,kernel)` : call代表函数调用，将kernel作为参数传递到totarget函数中；
* `$@` : 代表目标变量，如下代码中 `$@` 就代表kernel变量；
```
$(kernel): $(KOBJS)
    @echo + ld $@
```
* 语句开头的 `@` 符号代表不显示该语句；
* `dd` 函数代表拷贝和转换文件， `if` 参数代表入， `of` 参数代表出。

### 第二题

> 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？

该题可以从 `sign.c` 文件中找到答案，其主要完成如下任务：

1. 检查文件是否存在
2. 检查文件大小是否小于等于510字节
3. 读出文件到一个512字节的buffer中
4. 将buffer的最后两位置为 `0x55` 和 `0xAA`
5. 将buffer写入到输出文件中

由此可知，主引导扇区仅仅要求最后两个字节是`0x55` 和 `0xAA`，且其大小为512字节。

---

## 练习2
### 第一题

> 从 CPU 加电后执行的第一条指令开始,单步跟踪 BIOS 的执行。

修改tools/gdbinit，将其改为
```
set architecture i8086
target remote :1234
```
并执行 `make debug` ，得到gdb的调试界面，使用 `si` 命令即可单步调试BIOS。

由于本机gdb版本的问题，在处理8086实模式的时候会出现问题，gdb错误的认为程序执行的第一条指令地址为 `0xfff0` ，所以反汇编得到的指令全部是 `NOP` 。我采用了一个简单的解决方法，使用 `x /i 0xfffffff0` 手动查看指令内容，这样就可以跟踪BIOS的运行情况了。另外，还可以通过qemu的参数 `-d in_asm -D q.log` 将指令输出到文件之中。

### 第二题

> 在初始化位置0x7c00设置实地址断点,测试断点正常

更改gdbinit文件为

```
target remote :1234
b *0x7c00
c
x /10i $pc
```

输入 `make debug` 之后，打开gdb窗口，得到如下输出，可以使用 `si` 进行单步调试。

```asm
Breakpoint 1, 0x00007c00 in ?? ()
=> 0x7c00:      cli
   0x7c01:      cld
   0x7c02:      xor    %eax,%eax
   0x7c04:      mov    %eax,%ds
   0x7c06:      mov    %eax,%es
   0x7c08:      mov    %eax,%ss
   0x7c0a:      in     $0x64,%al
   0x7c0c:      test   $0x2,%al
   0x7c0e:      jne    0x7c0a
   0x7c10:      mov    $0xd1,%al
(gdb)
```

### 第三题

> 从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与bootasm.S和 bootblock.asm进行比较

修改gdbinit为

```
target remote :1234
b *0x7c00
c
set logging on
x /40i $pc
```

输入 `make debug` ，这样就将gdb的输出信息重定向到 `gdb.txt` 文件中去，得到如下结果。

```asm
=> 0x7c00:	cli    
   0x7c01:	cld    
   0x7c02:	xor    %eax,%eax
   0x7c04:	mov    %eax,%ds
   0x7c06:	mov    %eax,%es
   0x7c08:	mov    %eax,%ss
   0x7c0a:	in     $0x64,%al
   0x7c0c:  test   $0x2,%al
   0x7c0e:	jne    0x7c0a
   0x7c10:	mov    $0xd1,%al
   0x7c12:  out    %al,$0x64
   0x7c14:	in     $0x64,%al
   0x7c16:  test   $0x2,%al
   0x7c18:	jne    0x7c14
   0x7c1a:	mov    $0xdf,%al
   0x7c1c:  out    %al,$0x60
   0x7c1e:	lgdtl  (%esi)
   0x7c21:	insb   (%dx),%es:(%edi)
   0x7c22:	jl     0x7c33
   0x7c24:	and    %al,%al
   0x7c26:	or     $0x1,%ax
   0x7c2a:  mov    %eax,%cr0
   0x7c2d:  ljmp   $0xb866,$0x87c32
   0x7c34:  adc    %al,(%eax)
   0x7c36:  mov    %eax,%ds
   0x7c38:  mov    %eax,%es
   0x7c3a:  mov    %eax,%fs
   0x7c3c:  mov    %eax,%gs
   0x7c3e:  mov    %eax,%ss
   0x7c40:  mov    $0x0,%ebp
   0x7c45:  mov    $0x7c00,%esp
   0x7c4a:  call   0x7cd1
```

可以发现，和Bootasm.S以及bootblock.asm一致。

### 第四题

> 自己找一个bootloader或内核中的代码位置，设置断点并进行测试。

修改 gdbinit 文件为

```
target remote :1234
file bin/kernel
b kern_init
c
x /10i $pc
```

可以让gdb停留在 `kern_init` 函数，接下来可以进行单步调试。

---

## 练习3

> 分析bootloader进入保护模式的过程

当CPU完成BIOS初始化后，通过一条跳转指令跳转到 `0x7c00` 这个Bootloader的首地址，Bootloader首先初始化一些参数，

```asm
start:
.code16                             # Assemble for 16-bit mode
    cli                             # Disable interrupts
    cld                             # String operations increment

    # Set up the important data segment registers (DS, ES, SS).
    xorw %ax, %ax                   # Segment number zero
    movw %ax, %ds                   # -> Data Segment
    movw %ax, %es                   # -> Extra Segment
    movw %ax, %ss                   # -> Stack Segment
```
关闭中断使能，设置段寄存器为0。接着，Bootloader开启A20。

```asm
seta20.1:
    inb $0x64, %al      # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al     # 0xd1 -> port 0x64
    outb %al, $0x64     # 0xd1 means: write data to 8042's P2 port

seta20.2:
    inb $0x64, %al      # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al     # 0xdf -> port 0x60
    outb %al, $0x60     # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1
```
关于A20的意义，通过查阅资料，可以理解为在当时硬件条件不足的情况下的一个小trick，即借用键盘控制器8042的A20 Gate 来管理是否允许大于1M的内存地址空间，而后为了兼容性则一直遗留到了现在。A20的开启方法较为简单，首先等待键盘输入缓冲区清空，然后发送写8042输出端口的指令，再等待缓冲区没有数据后，打开A20。

```asm
    lgdt gdtdesc
    ......
# Bootstrap GDT
.p2align 2                                  # force 4 byte alignment
gdt:
    SEG_NULLASM                             # null seg
    SEG_ASM(STA_X|STA_R, 0x0, 0xffffffff)   # code seg for bootloader and kernel
    SEG_ASM(STA_W, 0x0, 0xffffffff)         # data seg for bootloader and kernel

gdtdesc:
    .word 0x17                              # sizeof(gdt) - 1
    .long gdt                               # address gdt


```

接着加载GDT表，由于此时一个简单的GDT表以及存放在内存中了，直接使用 `lgdt` 指令加载即可。这里初始化的GDT表非常简单，仅仅实现了物理地址的直接映射，这样能够保证在加载前后，Bootloader的代码不会发生位置的变化。

加载完成之后，进入保护模式，方法是将cr0寄存器的PE位置置为1即可，

```asm
    movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0

    # Jump to next instruction, but in 32-bit code segment.
    # Switches processor into 32-bit mode.
    ljmp $PROT_MODE_CSEG, $protcseg
```
这样就跳转到了32位指令空间protcseg的位置。最后，参照C调用的堆栈惯例，建立好一个初始的堆栈（0到0x7c00），供bootmain.c中的bootmain函数使用

```asm
.code32                             # Assemble for 32-bit mode
protcseg:
    # Set up the protected-mode data segment registers
    movw $PROT_MODE_DSEG, %ax       # Our data segment selector
    movw %ax, %ds                   # -> DS: Data Segment
    movw %ax, %es                   # -> ES: Extra Segment
    movw %ax, %fs                   # -> FS
    movw %ax, %gs                   # -> GS
    movw %ax, %ss                   # -> SS: Stack Segment

    # Set up the stack pointer and call into C. The stack region is from 0--start(0x7c00)
    movl $0x0, %ebp
    movl $start, %esp
    call bootmain
```
这样，就完成了汇编码到C码的转换。在bootmain函数中，程序加载了硬盘上的Ucore操作系统，并将其代码段数据段分别放在合适的位置，最后跳转到Ucore的入口地址，至此完成全部Bootloader的任务。

---

##练习4

> 分析bootloader加载ELF格式的OS的过程

在bootmain函数的一开始，通过 `readseg` 函数读取ELF Header。其参数为

```c
readseg(uintptr_t va, uint32_t count, uint32_t offset)
```

分别代表读取存放位置的虚拟地址，读取内容的长度和读取的偏移量。其实现如下：
```c
    uintptr_t end_va = va + count;

    // round down to sector boundary
    va -= offset % SECTSIZE;

    // translate from bytes to sectors; kernel starts at sector 1
    uint32_t secno = (offset / SECTSIZE) + 1;

    // If this is too slow, we could read lots of sectors at a time.
    // We'd write more to memory than asked, but it doesn't matter --
    // we load in increasing order.
    for (; va < end_va; va += SECTSIZE, secno ++) {
        readsect((void *)va, secno);
    }
```
首先计算读取的第一块扇区编号是多少，接着反复调用 `readsect` 函数读取每一块扇区来完成磁盘的读取。

`readsect` 函数主要实现了从一个扇区读取内容并存放到内存中这一个简单的功能，其主要实现为：

```c
static void
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                         // count = 1
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors

    // wait for disk to be ready
    waitdisk();

    // read a sector
    insl(0x1F0, dst, SECTSIZE / 4);
}
```

首先等待磁盘空闲，接着将参数输出到 `0x1F2~0x1F7`，告诉硬盘需要读取的扇区个数，扇区编号和读取操作的操作编号。其中 `0x1F3~0x1F6` 为扇区编号的前27位， `0x1F6` 的最后一位区分主从盘。发出了操作请求后，继续等待磁盘空闲，最后将数据从 `0x1F0` 读取到内存中去，完成一个扇区的读取。

回到bootmain函数，通过刚刚的操作读取了ELF头之后，首先检查ELF头是否正确，即检查ELF头一个32位是不是 `ELF_MAGIC` 这个常数。

```c
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }
```

检查通过之后，通过ELF表找到program header表的位置偏移和数目，并分别将他们加载到内存相应的位置中去。

```c
    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }
```

在实际的测试过程中，共有两个program header，第一个被载入内存 `0x00100000` ，第二个被载入内存 `0x0010E000`。

```c
    // call the entry point from the ELF header
    // note: does not return
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();
```

最后，在全部Ucore被加载完成到内存之后，通过ELF头中指定的Ucore入口地址，bootmain函数调用Ucore入口函数，从而成功启动操作系统。

---

## 练习5

> 实现函数调用堆栈跟踪函数

实现代码如下

```c
    uint32_t ebp = read_ebp();
	uint32_t eip = read_eip();
	int i = 0;

	while(i < STACKFRAME_DEPTH) {
		cprintf("ebp:0x%08x eip:0x%08x args:0x%08x 0x%08x 0x%08x 0x%08x\n", ebp, eip, *((uint32_t*)ebp+2), *((uint32_t*)ebp+3), *((uint32_t*)ebp+4), *((uint32_t*)ebp+5));
		print_debuginfo(eip - 1);
		eip = *((uint32_t*)ebp + 1);
		ebp = *(uint32_t*)ebp;
		i++;
		if(ebp == 0)
			break;
	}
```

首先调用 `read_ebp()` 和 `read_eip()` 函数获得两个寄存器值，然后使用循环输出这两个寄存器值以及参数值，再通过 `eip  = ss:[ebp+4]` 和 `ebp = ss:[ebp]` 获得上层栈的信息，以此类推。

最后输出为

```
ebp:0x00007b08 eip:0x001009a7 args:0x00010094 0x00000000 0x00007b38 0x00100092
    kern/debug/kdebug.c:306: print_stackframe+22
ebp:0x00007b18 eip:0x00100c7c args:0x00000000 0x00000000 0x00000000 0x00007b88
    kern/debug/kmonitor.c:125: mon_backtrace+10
ebp:0x00007b38 eip:0x00100092 args:0x00000000 0x00007b60 0xffff0000 0x00007b64
    kern/init/init.c:48: grade_backtrace2+33
ebp:0x00007b58 eip:0x001000bb args:0x00000000 0xffff0000 0x00007b84 0x00000029
    kern/init/init.c:53: grade_backtrace1+38
ebp:0x00007b78 eip:0x001000d9 args:0x00000000 0x00100000 0xffff0000 0x0000001d
    kern/init/init.c:58: grade_backtrace0+23
ebp:0x00007b98 eip:0x001000fe args:0x0010349c 0x00103480 0x0000130a 0x00000000
    kern/init/init.c:63: grade_backtrace+34
ebp:0x00007bc8 eip:0x00100055 args:0x00000000 0x00000000 0x00000000 0x00010094
    kern/init/init.c:28: kern_init+84
ebp:0x00007bf8 eip:0x00007d68 args:0xc031fcfa 0xc08ed88e 0x64e4d08e 0xfa7502a8
    <unknow>: -- 0x00007d67 --
```

最后一行代表最深的调用栈，即 `call bootmain` 指令对应的 `bootmain` 函数栈。由于bootloader设置的堆栈从 `0x7c00` 开始，所以 `bootmain` 函数栈从 `0x7bf8` 开始。

---

## 练习6

> 完善中断初始化和处理 

### 第一题

> 中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？

一个表项占 `8` 字节，其中第 `2/3` 字节是 `段选择子` ，第 `0/1` 字节和第 `6/7` 字节拼成位移，二者加在一起为入口地址。

### 第二题

> 请编程完善kern/trap/trap.c中对中断向量表进行初始化的函数idt_init。在idt_init函数中，依次对所有中断入口进行初始化。使用mmu.h中的SETGATE宏，填充idt数组内容。每个中断的入口由tools/vectors.c生成，使用trap.c中声明的vectors数组即可。

代码如下：

```c
	extern uintptr_t __vectors[];
	int i;
	for(i = 0; i < 256; ++i) {
		SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
	}
	SETGATE(idt[T_SWITCH_TOK], 0, GD_KTEXT, __vectors[T_SWITCH_TOK], DPL_USER);

	lidt(&idt_pd);
```

`__vectors` 变量代表中断入口的起始位置，在汇编文件中有定义。首先初始化各个GATE，使其依次对应中断入口中的相应位置；接着处理能在用户态触发的中断，允许其正在用户态触发；最后设置全局中断处理向量表即可。

### 第三题

> 请编程完善trap.c中的中断处理函数trap，在对时钟中断进行处理的部分填写trap函数中处理时钟中断的部分，使操作系统每遇到100次时钟中断后，调用print_ticks子程序，向屏幕上打印一行文字”100 ticks”。

此步骤较为简单，代码如下

```c
	case IRQ_OFFSET + IRQ_TIMER:
		if(++ticks % TICK_NUM == 0) {
			print_ticks();
		}
		break;
```
