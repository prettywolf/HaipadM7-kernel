zreladdr-y	:= 0x20008000
params_phys-y	:= 0x20000100

# override for Herring
zreladdr-$(CONFIG_MACH_HERRING)	:= 0x30008000
params_phys-$(CONFIG_MACH_HERRING)	:= 0x30000100

# override for SMDKC110
#zreladdr-$(CONFIG_MACH_SMDKC110)	:= 0x30008000
#params_phys-$(CONFIG_MACH_SMDKC110)	:= 0x30000100

# override for CTC SMDKV210
#zreladdr-$(CONFIG_MACH_SMDKV210_CTC)	:= 0x30008000
#params_phys-$(CONFIG_MACH_SMDKV210_CTC)	:= 0x30000100
