// SPDX-License-Identifier: MIT OR Apache-2.0
// Regenerate: iasl -p peripherals peripherals.asl
DefinitionBlock ("", "DSDT", 2, "CRABEF", "PERIPHS", 1)
{
    Name (TPST, 0x0F)
    Name (BUSS, Zero)
    Name (GPST, 0x0F)
    Name (PWR0, Zero)
    Method (DSTP, 0) { TPST = Zero }
    Method (DSBS, 0) { BUSS = Zero }
    Method (DSGP, 0) { GPST = Zero }
    Method (SLPB, 0) { PWR0 = 3 }
    Method (POFF, 0) { \_SB.I2C2.PWRR._OFF () }
    Scope (\_SB)
    {
        Device (GPIO)
        {
            Name (_HID, "AMD0030")
            Method (_STA, 0) { Return (GPST) }
            Name (_CRS, ResourceTemplate () { Memory32Fixed (ReadWrite, 0xFED81500, 0x400) })
        }
        Device (EMMC)
        {
            Name (_HID, "AMDI0040")
            Method (_STA, 0) { Return (TPST) }
            Method (_PSC, 0) { Return (PWR0) }
            Name (_PR0, Package () { \_SB.I2C2.PWRR })
            Name (_CRS, ResourceTemplate () { Memory32Fixed (ReadWrite, 0xFEDD5000, 0x1000) })
        }
        Device (PCI0)
        {
            Name (_HID, EisaId ("PNP0A08"))
            Name (_UID, Zero)
            Device (GPIO)
            {
                Name (_HID, "AMD0030")
                Name (_UID, One)
                Name (_CRS, ResourceTemplate () { Memory32Fixed (ReadWrite, 0xDEADB000, 0x400) })
            }
            Device (I2C2)
            {
                Name (_HID, "AMDI0010")
                Name (_UID, One)
                Name (_CRS, ResourceTemplate () { Memory32Fixed (ReadWrite, 0xDEADC000, 0x1000) })
            }
        }
        Device (I2C2)
        {
            Name (_HID, "AMDI0010")
            Name (_UID, 2)
            Method (_STA, 0) { Return (BUSS) }
            Method (_PSC, 0) { Return (PWR0) }
            PowerResource (PWRR, 0, 0)
            {
                Name (STAT, One)
                Method (_STA, 0) { Return (STAT) }
                Method (_ON, 0) { STAT = One }
                Method (_OFF, 0) { STAT = Zero }
            }
            Name (_PR0, Package () { PWRR })
            Name (_CRS, ResourceTemplate () { Memory32Fixed (ReadWrite, 0xFEDC4000, 0x1000) })
            Device (TPAD)
            {
                Name (_HID, "ELAN0000")
                Method (_STA, 0) { Return (TPST) }
                Name (_CRS, ResourceTemplate () {
                    I2cSerialBusV2 (0x15, ControllerInitiated, 400000, AddressingMode7Bit,
                        "^^I2C2", 0, ResourceConsumer, , Exclusive, )
                    GpioInt (Level, ActiveLow, ExclusiveAndWake, PullDefault, 0,
                        "\\_SB.GPIO", 0, ResourceConsumer, , ) { 9 }
                })
            }
            Device (GSC0)
            {
                Name (_HID, "GOOG0005")
                Name (_CRS, ResourceTemplate () {
                    I2cSerialBusV2 (0x50, ControllerInitiated, 400000, AddressingMode7Bit,
                        "\\_SB.I2C2", 0, ResourceConsumer, , Exclusive, )
                    GpioInt (Edge, ActiveLow, Exclusive, PullNone, 0,
                        "\\_SB.GPIO", 0, ResourceConsumer, , ) { 3 }
                })
            }
            Device (MISS)
            {
                Name (_HID, "ELAN0000")
                Name (_CRS, ResourceTemplate () {
                    I2cSerialBusV2 (0x15, ControllerInitiated, 400000, AddressingMode7Bit,
                        "\\_SB.MISS", 0, ResourceConsumer, , Exclusive, )
                    GpioInt (Level, ActiveLow, Exclusive, PullDefault, 0,
                        "\\_SB.GPIO", 0, ResourceConsumer, , ) { 9 }
                })
            }
        }
    }
    // Coreboot's SSDT enables a controller's initially-zero STAT at table load.
    Store (0x0F, \BUSS)
}
