---
slug: analytics
title: Linux
tags:
  - systems
  - linux
---

# **LINUX**

<figure markdown>
  ![](../../../assets/img/hero/5aeb4a0f6e453ce98b2506f3259f2fc4.jpeg){ .skip-lightbox }
</figure>

The boot process on linux is divided into four stages.

### **Bootstrap Phase**

This is the first stage where your machine comes to life from a state of complete inactivity. We'll walk through this step-by-step, focusing on the three types of bootstrapping: BIOS, UEFI, and PXE.

#### BIOS (Basic Input/Output System)

1. **Power On**: You hit the power button, and your machine starts up. The CPU is activated and searches for the BIOS firmware instructions.

2. **POST (Power-On Self Test)**: The BIOS performs POST to check the hardware integrity like memory, keyboard, and other peripherals.

3. **BIOS Settings**: After POST, BIOS looks into its configured settings in the CMOS (Complementary Metal-Oxide-Semiconductor).

4. **Boot Device Selection**: BIOS checks the boot device order to find where the bootloader is. Typically, it could be a hard drive, CD/DVD, or USB drive.

5. **Bootloader Handoff**: Once the BIOS identifies the correct boot device with a valid bootloader, it hands over control to the bootloader's first stage (like GRUB or LILO in Linux).

---

#### UEFI (Unified Extensible Firmware Interface)

1. **Power On**: Similar to BIOS, the system is powered on, and the CPU starts looking for instructions, which in this case, are from the UEFI firmware.

2. **Self-tests and Initialization**: UEFI runs its own version of POST and initializes the hardware components.

3. **UEFI Boot Manager**: Unlike BIOS, UEFI comes with a boot manager which makes it easier to manage and select various boot devices.

4. **Boot Device Detection**: UEFI checks the list of boot devices stored in its NVRAM (Non-Volatile RAM), which doesn't require a battery to maintain the storage, unlike CMOS in BIOS.

5. **EFI System Partition (ESP)**: UEFI looks for the EFI System Partition, which contains the bootloader files.

6. **Bootloader Execution**: After locating the correct ESP, UEFI executes the bootloader, which then proceeds to load the kernel.

---

#### PXE (Preboot Execution Environment)

1. **Start-Up**: The machine is powered on, and the network card's PXE firmware kicks in.

2. **Network Initialization**: The network card initializes and sends out a broadcast request to find a PXE server.

3. **DHCP and IP Assignment**: A DHCP server assigns an IP address to the machine for network communication.

4. **Boot Server Contact**: The PXE-enabled network card contacts the boot server from where it will retrieve the boot file.

5. **Boot File Download**: The machine downloads the boot file (like a Linux kernel) via TFTP (Trivial File Transfer Protocol) or other network protocols.

6. **Bootloader Transfer**: The downloaded file typically includes a bootloader that the machine then executes to continue the boot process.

---

Now that we have covered the Bootstrap Phase, you should have a clear understanding of how a Linux system starts up, depending on whether it's using BIOS, UEFI, or PXE. Each method has its own unique steps but ultimately, they all serve the purpose of getting the system ready to hand over control to the bootloader, which then leads us into the next phase of the Linux Boot Process.

### **Bootloader Phase**

This is where the system really starts to get its bearings and prepares to launch the operating system. We'll focus on GRUB, which is one of the most commonly used bootloaders on Linux systems, and touch on LILO as another example.

---

#### GRUB (GNU GRand Unified Bootloader)

##### GRUB Stages

1. **Stage 1 (Primary Bootloader)**: This is the first thing GRUB loads. It's very small and resides in the MBR (Master Boot Record) or the boot sector of your partition. Its job is to load Stage 2 or 1.5.

2. **Stage 1.5 (Optional)**: This stage is loaded if Stage 2 can't be loaded directly due to filesystem complexity. It understands the filesystem and helps in loading Stage 2. It's located in the disk sectors immediately following the MBR.

3. **Stage 2 (Secondary Bootloader)**: This is the core of GRUB. It presents the menu and loads the selected kernel into memory. It resides in the /boot/grub directory.

##### GRUB Menu

-   **Menu Display**: When Stage 2 loads, you usually see a menu that lists the available kernels and operating systems you can boot. This is defined in the GRUB configuration file (grub.cfg).

-   **Selection**: You can select which kernel or operating system to boot either with a default set by the timer or by manual selection.

-   **Editing Options**: If needed, you can edit the boot parameters on the fly at this menu. This is useful for troubleshooting or for advanced configuration.

##### GRUB Interactive Boot

-   **Interactive Commands**: If you press 'c' at the GRUB menu, you enter the GRUB command line, which allows you to manually boot your system or troubleshoot issues.

-   **Kernel Parameters**: From here, you can specify kernel parameters or boot to different runlevels. This is a powerful feature for system recovery or diagnostics.

---

#### LILO (Linux Loader)

-   **Simpler Approach**: LILO is an older bootloader which doesn't have stages like GRUB. It's straightforward and was quite popular before GRUB became the standard.

-   **Configuration**: LILO configuration is handled by the `/etc/lilo.conf` file, where you define the kernel images and boot options.

-   **No Interactive Mode**: Unlike GRUB, LILO does not have an interactive command-line mode. If you need to change boot parameters, you must do so within the configuration file and then rerun the LILO command to apply the changes.

-   **Loading**: When LILO is selected as the bootloader, it directly loads the kernel and initial RAM disk specified in the configuration file and starts the system.

---

While GRUB is more feature-rich and has largely replaced LILO in modern systems, both serve the critical function of loading the Linux kernel from the filesystem into memory. This sets the stage for the actual booting of the Linux operating system, which we'll explore in the Kernel Phase.

### **Kernel Phase**

This is where the Linux kernel takes center stage. After being loaded by the bootloader, the kernel initializes the system and gets everything ready for the final phase. Let's break it down.

---

#### Kernel Initialization

1. **Loading**: The selected kernel image is loaded into memory by the bootloader. This is the uncompressed, compiled kernel that the system will use.

2. **Decompression**: The kernel is typically compressed to save space and speed up the loading process. The first thing it does is decompress itself.

3. **Hardware Detection**: Once decompressed, the kernel starts detecting the hardware on the system. It checks for the CPU, RAM, and other essential hardware components.

4. **Initialization**: The kernel initializes the detected hardware and prepares the drivers necessary for their operation.

5. **Mount Root Filesystem**: The kernel mounts the root filesystem as read-only initially. This is crucial because it contains all the files needed for the system to operate.

6. **Init Process**: After mounting the root filesystem, the kernel starts the `init` process (or an alternative like `systemd` or `Upstart`). This is the first user-space process, with a process ID (PID) of 1, which takes over the boot process from the kernel.

---

#### Kernel Boot Parameters

-   **Passing Parameters**: During boot, the bootloader may pass parameters to the kernel to influence its behavior. These can include things like the root device, various hardware options, or system performance settings.

-   **Runlevels**: The kernel can also be instructed to boot into a specific runlevel, which defines what services and features are started. This can be essential for troubleshooting or running a server with minimal resources.

---

#### System Initialization Scripts

-   **Scripts and Targets**: Once the `init` process starts, it runs a series of scripts or targets, depending on whether the system uses a traditional init system or something like `systemd`. These scripts start all the necessary services and get everything ready for user interaction.

-   **Final Steps**: Just before handing over control to the user, the system will perform a few last steps like setting the clock, starting network services, and running any final system initialization scripts.

---

With the Kernel Phase complete, the system is almost ready to be used. The kernel has done its job of setting up the core components and has handed over control to the initialization system, which will bring the system into a fully operational state. Next up, we'll explore the Initialization Phase, where all the pieces come together, and the system becomes ready for login and use.

### **Initialization Phase**

The final stretch before the system is ready for use. In this phase, the system's initialization process takes the baton from the kernel and starts up services and user environments. Additionally, I'll explain the role of `initrd`, `mkinitrd`, `initramfs`, `mkinitramfs`, and `dracut` as they're quite relevant to this stage.

---

#### System and Service Initialization

1. **Init Process**: The `init` process (or its modern replacements like `systemd` or `Upstart`) is now fully in control, following the instructions from the kernel.

2. **Runlevel/Target Services**: Depending on the system configuration, different services are started according to the default runlevel or target. This includes networking, logging, graphical interfaces, and more.

3. **Final System Configuration**: Any system-wide scripts or user scripts are executed to finalize the configuration before the login prompt is presented.

4. **Login Prompt**: Once all services are started, the system displays a login prompt, either in the console or through a graphical display manager, depending on the system setup.

---

#### Understanding initrd, mkinitrd, initramfs, mkinitramfs, and dracut

##### initrd (Initial RAM Disk)

-   **Purpose**: `initrd` is a temporary root filesystem used during the initial boot process. It contains necessary drivers and scripts needed to mount the real root filesystem.

##### mkinitrd (Make Initial RAM Disk)

-   **Function**: `mkinitrd` is a command used to create an `initrd` image. This command compiles a collection of modules and necessary tools to successfully boot the system when kernel does not have built-in support for certain filesystems or hardware.

##### initramfs (Initial RAM Filesystem)

-   **Evolution**: `initramfs` is the successor to `initrd`. It's a cpio archive of the initial filesystem that gets loaded into memory by the kernel during the boot process. Unlike `initrd`, which is a block device, `initramfs` is a filesystem archive.

##### mkinitramfs (Make Initial RAM Filesystem)

-   **Usage**: `mkinitramfs` is the tool used to create an `initramfs` image. It's typically used on systems that have replaced `initrd` with `initramfs`.

##### dracut

-   **Description**: `dracut` is a more modern replacement for `mkinitrd`/`mkinitramfs`. It creates an `initramfs` image that can be used by various Linux distributions. It's designed to have a modular structure and be highly customizable.

---

Each of these tools plays a critical role in the boot process. They prepare a minimal environment that the kernel can use to get the system up and running before the actual root filesystem is available. This is especially important for systems that require drivers that aren't included in the kernel itself.

With the Initialization Phase complete, the system is now fully booted and ready for user interaction. You can log in and start using the Linux system, confident in the knowledge of what's happened behind the scenes to get you to this point.
