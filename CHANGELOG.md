## April 2025 (v1.0.0.5)
### Bug Fixes
- Corrected variable in "Goto location" print statement to display accurate file offset information.

## March 2025 (v1.0.0.4)
### New Features
- Added "Copy FO" command (Shift-W)
- Added "Goto clipboard FO" command (Ctrl-Shift-G)

### Improvements
- Enhanced output to display whether you are going to EA, FO or named function
- Renamed "Convert to" -> "Dump as" for more accurate functionality description

### Bug Fixes
- Fixed parse_location, restoring the ability to navigate to named functions
- Fixed missing badaddr check in HexRaysView
- Normalized command descriptions across IDAView and HexRaysView

## August 2024 - November 2024 (v1.0.0.3)
### Major Changes
- Added support for IDA 9.0

### Bug Fixes
- Fixed widget type checks for IDA 9.0 compatibility
- Added try/except handling for BWN_HEXVIEW/BWN_DUMP compatibility
- Fixed typo in inf_is_16bit function

## October 2022 - February 2022
### Bug Fixes
- Fixed TypeError when get_highlight returns None
- Corrected selection size calculation for proper data extraction

## June 2021
### Improvements
- Implemented automatic copying of conversion results to clipboard
- Removed dependency on external clipboard libraries

## September 2017 - April 2018 (v1.0.0.2)
### Major Changes
- Added full support for IDA 7.0 and 7.1
- Added Python 3 compatibility

### Bug Fixes
- Fixed UI element access methods for IDA 7.0+
- Replaced deprecated IDA API attributes
- Fixed bug in copy function name feature

## December 2016 - February 2018 (v1.0.0.1)
### Improvements
- Added toggle functionality to remove/restore function return types
- Enhanced format string vulnerability detection on different architectures
- Fixed various memory handling issues for data conversion

## June 2016 - August 2016
### New Features
- Added "Get xored data" feature for binary analysis
- Added "Fill with NOPs" functionality for code patching
- Implemented auto-jump to virtual functions on double click
- Added support for word-sized data in conversion functions
- Enhanced format string vulnerability detection for x86 and ARM

## Initial Release (June 12, 2016)
### Features
- Remove function return type in Hex-Rays decompiler
- Convert data into different formats (strings, hex strings, C arrays, Python lists)
- Scan for format string vulnerabilities
- Lazy shortcuts for common operations
