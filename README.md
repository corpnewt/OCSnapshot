# OCSnapshot
Python CLI version of ProperTree's OC Snapshot function.

```
usage: OCSnapshot.command [-h] [-i INPUT_FILE] [-o OUTPUT_FILE] [-s SNAPSHOT] [-c]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input-file INPUT_FILE
                        Path to the input plist - will use an empty dictionary if none passed.
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Path to the output plist if different than input.
  -s SNAPSHOT, --snapshot SNAPSHOT
                        Path to the OC folder to snapshot.
  -c, --clean-snapshot  Remove existing ACPI, Kernel, Driver, and Tool entries before adding anew.
  ```
