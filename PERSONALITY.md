# EdgeProtect Bootloader Configuration Personality

## Table of Contents

- [Overview](#overview)
- [How to Use This Personality](#how-to-use-this-personality)
- [Configuration Categories](#configuration-categories)
- [Memory Layout Configuration](#memory-layout-configuration)
- [Generated Configuration Files](#generated-configuration-files)
- [Quick Reference Tables](#quick-reference-tables)

## Overview

The **EdgeProtect Bootloader Configuration** personality is a ModusToolbox Device Configurator plugin that provides a comprehensive GUI-based interface for configuring bootloader applications built using the `ifx-mcuboot-pse84` middleware.

**What this personality does:**
- Configures the `ifx-mcuboot-pse84` middleware for your specific bootloader application
- Generates configuration headers, makefiles, and JSON files for your project
- Sets up memory layouts for multi-core PSE84 bootloader applications
- Configures security settings, encryption keys, and signing parameters

**What you configure with this personality:**
- Your bootloader's memory layout and slot allocation
- Security features like encryption, signature validation, and rollback protection
- Multi-core coordination settings for CM33 and CM55 applications
- Build integration for your specific bootloader project

## How to Use This Personality

### Step 1: Access the Configuration Interface

1. **Open Your Bootloader Project**
   - Navigate to the bootloader project that uses `ifx-mcuboot-pse84` middleware
   - Ensure the middleware is already added to your project

2. **Launch Device Configurator**
   - Open ModusToolbox Device Configurator
   - Select "Solution" tab in Device Configurator

3. **Add the Personality**
   - Enable "EdgeProtect Bootloader Configuration"
   - The personality will appear in your configuration workspace

### Step 2: Configure Your Bootloader Application

The personality organizes configuration into logical groups for your bootloader:

## Configuration Categories

Use these configuration sections to set up your bootloader application:

### 🔧 Basic Bootloader Configuration (MCUBoot Config)

Configure the core behavior of your bootloader application:

| Setting | Options | Default | How It Affects Your Bootloader |
|---------|---------|---------|--------------------------------|
| **Upgrade Mode** | `overwrite`, `swap` | `overwrite` | Determines how your bootloader handles firmware updates |
| **Logging Level** | `off`, `dbg`, `inf`, `wrn`, `err` | `dbg` | Controls debug output verbosity in your bootloader |
| **FIH Level** | `off`, `low`, `med`, `high` | `off` | Sets fault injection hardening level for security |
| **Image Count** | 1-5 | `3` | Number of application images your bootloader will manage |
| **Validate Boot Slot** | true/false | `false` | Whether your bootloader validates primary slots at boot |
| **Validate Upgrade Slot** | true/false | `false` | Whether your bootloader validates upgrade slots |
| **Measured Boot** | true/false | `false` | Enables attestation functionality in your bootloader |
| **HW Rollback Protection** | true/false | `false` | Enables hardware anti-rollback protection |

### 🔐 Security Configuration for Your Bootloader (Image Encryption)

Configure how your bootloader handles encrypted applications:

| Setting | Options | Default | Purpose in Your Bootloader |
|---------|---------|---------|----------------------------|
| **Encryption Mode** | `off`, `xip_single_key` | `off` | Type of image encryption your bootloader supports |
| **KEK Address** | Hex address | `0x3203A000` | Where your bootloader stores private keys in RRAM |
| **Public KEK Path** | File path | - | Public ECC key file for your bootloader build |
| **AES128 DEK Path** | File path | - | AES encryption key file for your bootloader |
| **NONCE Output Path** | File path | - | Generated nonce file for encryption |

### 🏗 Application Slot Configuration

Configure how your bootloader manages the applications it boots:

**Memory Configuration for Each Application:**
- **Primary Slot**: Configure memory type, offset, size, and secure access for each application your bootloader manages
- **Secondary Slot**: Set up upgrade storage location and size for firmware updates
- **RAM Load**: Enable RAM execution with region selection for high-performance applications

**Build & Deployment Integration:**
- **Project Name**: Identify the application project your bootloader will boot
- **Hex File Paths**: Specify input/output file locations for signing and combining
- **Private Key Path**: Set signing key location for application verification
- **Image Version**: Configure version for rollback protection
- **Dependencies**: Define inter-application dependencies for your bootloader

## Memory Layout Configuration

### Configuring Memory for Your Bootloader Application

The personality helps you configure memory regions that your bootloader will use to manage applications:

### Memory Region Types for Your Bootloader

| Memory Type | When to Use | How Your Bootloader Uses It |
|-------------|-------------|------------------------------|
| **RRAM** | Primary application storage | Your bootloader executes applications directly from internal RRAM |
| **SRAM** | High-performance execution | Your bootloader loads applications to SRAM for fastest execution |
| **SMIF** | Large applications/updates | Your bootloader stores upgrade images in external SMIF flash |
| **ITCM** | Critical code execution | Your bootloader can execute applications from instruction cache |
| **SOCMEM** | Shared system resources | Your bootloader manages shared memory regions |

### Step 3: Configure Memory Layout

1. **Set Bootloader Region**
   - Configure where your bootloader code will reside (typically at offset `0x00011000`)
   - Size the region appropriately for your bootloader implementation

2. **Configure Application Slots**
   - Primary slots: Where your bootloader finds applications to execute
   - Secondary slots: Where your bootloader expects upgrade images
   - Ensure no memory overlaps between regions

3. **Set Key Storage**
   - Configure secure RRAM region for your bootloader's encryption key

## Generated Configuration Files

### Step 4: Build Your Configured Bootloader

The personality automatically generates configuration files that integrate with your bootloader project:

### Core Configuration Files for Your Bootloader
| File | Location | What It Configures in Your Bootloader |
|------|----------|---------------------------------------|
| `mcuboot_config.h` | `GeneratedSource/` | Feature flags and memory definitions for the ifx-mcuboot-pse84 middleware |
| `memorymap.h/.c` | `GeneratedSource/` | Memory layout and flash area configs your bootloader will use |
| `feature_config.mk` | `GeneratedSource/` | Build-time feature selection for your bootloader compilation |

### Signer-Combiner Files for Your Project
| File | Purpose | How Your Project Uses It |
|------|---------|--------------------------|
| `boot_with_bldr.json` | Boot image configuration | Combines your bootloader with applications during build |
| `boot_with_bldr_upgr.json` | Upgrade image configuration | Configures upgrade image generation for your applications |

### Configuration Macros

These macros are automatically generated based on your personality configuration:

#### Core Configuration
```c
/* Multi-core support - set via personality */
#define MCUBOOT_IMAGE_NUMBER        3    /* Number of images (CM33_S, CM33_NS, CM55) */

/* Security features - enabled via personality */
#define MCUBOOT_ENC_IMAGES          1    /* Enable image encryption support */
#define MCUBOOT_VALIDATE_PRIMARY_SLOT 1 /* Validate primary slot at boot */
#define MCUBOOT_VALIDATE_UPGRADE_SLOT  1 /* Validate upgrade slot */

/* Boot modes - configured via personality */
#define MCUBOOT_DIRECT_XIP          1    /* Enable execute-in-place mode */
#define MCUBOOT_RAM_LOAD            1    /* Enable RAM loading capability */

/* Memory configuration - set via personality */
#define CUSTOM_KEY_ENC_KEY_ADDR     0x3203A000  /* RRAM address for encryption keys */
```

#### Advanced Security
```c
/* Hardware security - enabled via personality */
#define MCUBOOT_HW_ROLLBACK_PROT    1    /* Hardware rollback protection */
#define MCUBOOT_MEASURED_BOOT       1    /* Measured boot functionality */

/* Fault injection hardening - configured via personality */
#define MCUBOOT_FIH_PROFILE_HIGH    1    /* Maximum fault injection protection */

/* Cryptographic algorithms - enabled based on personality settings */
#define MCUBOOT_SIGN_EC256          1    /* ECDSA P-256 signature support */
#define MCUBOOT_ENC_IMAGES_XIP      1    /* XIP encryption support */
```

### Memory Map Interface

Use these APIs to interact with flash areas in your bootloader:

#### Flash Area Definitions
```c
/**
 * Flash area structure for memory region management
 * Used by the middleware to abstract different memory types
 */
struct flash_area {
    uint8_t  fa_id;        /* Flash area identifier */
    uint8_t  fa_device_id; /* Device identifier */
    uint16_t pad16;        /* Padding for alignment */
    uint32_t fa_off;       /* Offset within device */
    uint32_t fa_size;      /* Size of flash area */
};

/**
 * Get flash area by ID
 * Use this to access configured memory regions
 * @param id Flash area identifier (see memory region IDs below)
 * @param fa Pointer to flash area structure
 * @return 0 on success, error code on failure
 */
int flash_area_open(uint8_t id, const struct flash_area **fa);

/**
 * Close flash area
 * Call when done with flash area operations
 * @param fa Flash area pointer
 */
void flash_area_close(const struct flash_area *fa);
```

### Integration with Your Bootloader Build

After configuration, your bootloader project will:

1. **Include Generated Headers**: Your bootloader source automatically includes the generated `mcuboot_config.h`
2. **Use Memory Layout**: The middleware uses `memorymap.h/.c` to understand your memory configuration
3. **Apply Build Features**: The generated `feature_config.mk` is included in your bootloader's Makefile
4. **Sign and Combine**: The JSON files integrate with ModusToolbox build system to sign your bootloader and applications

## Quick Reference Tables

### Essential Configuration Parameters for Your Bootloader

| Parameter | Default | Options | How It Affects Your Bootloader |
|-----------|---------|---------|--------------------------------|
| `upgrade_mode` | `overwrite` | `overwrite`, `swap` | Update strategy your bootloader uses |
| `logging_level` | `dbg` | `off`, `dbg`, `inf`, `wrn`, `err` | Debug verbosity in your bootloader output |
| `image_count` | `3` | 1-5 | Number of applications your bootloader manages |
| `image_encryption` | `off` | `off`, `xip_single_key` | Encryption mode your bootloader supports |
| `key_encryption_key_address` | `0x3203A000` | Hex address | Where your bootloader stores encryption keys |

### Memory Configuration Parameters for Your Bootloader

| Parameter | Purpose | Typical Value | What Your Bootloader Uses It For |
|-----------|---------|---------------|----------------------------------|
| `bootloader_var_offset` | Bootloader start address | `0x00011000` | Where your bootloader code is located |
| `bootloader_var_size` | Bootloader code size | `0x00028000` | Size allocated for your bootloader |
| `app0_manual_primary_offset` | App 0 primary slot | `0x00039000` | Where your bootloader finds first application |
| `app0_manual_primary_size` | App 0 slot size | `0x00100000` | Size of first application your bootloader manages |

### Generated Files Your Bootloader Project Uses

| File | Location | Purpose in Your Bootloader Project |
|------|----------|-------------------------------------|
| `mcuboot_config.h` | `GeneratedSource/` | Feature configuration for ifx-mcuboot-pse84 middleware |
| `memorymap.h/.c` | `GeneratedSource/` | Memory layout your bootloader uses |
| `feature_config.mk` | `GeneratedSource/` | Build configuration for your bootloader |
| `boot_with_bldr.json` | `GeneratedSource/` | Signer configuration for your project build |

---

### 📄 License & Copyright

**© Cypress Semiconductor Corporation (an Infineon company) or an affiliate of Cypress Semiconductor Corporation, 2023-2025.**

This personality configuration documentation is provided under the terms of the [Infineon Software License Agreement](https://www.infineon.com/cms/en/about-infineon/company/legal/terms-of-use/software-license-agreement/).

---

*Last updated: September 2025 | Document version: 1.2*
