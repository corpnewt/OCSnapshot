#!/usr/bin/env python
import argparse, os, hashlib
from Scripts import *

class OCSnapshot:
    def __init__(self):
        self.u = utils.Utils("OC Snapshot")
        self.r = run.Run()
        self.snapshot_data = {}
        if os.path.exists("Scripts/snapshot.plist"):
            try:
                with open("Scripts/snapshot.plist","rb") as f:
                    self.snapshot_data = plist.load(f)
            except: pass

    def get_min_max_from_match(self, match_text):
        # Helper method to take MatchKernel output and break it into the MinKernel and MaxKernel
        temp_min = "0.0.0"
        temp_max = "99.99.99"
        match_text = "" if match_text == "1" else match_text # Strip out "1" in prefix matching to match any
        if match_text != "":
            try:
                min_list = match_text.split(".")
                max_list = [x for x in min_list]
                min_list += ["0"] * (3-len(min_list)) # pad it out with 0s for min
                min_list = [x if len(x) else "0" for x in min_list] # Ensure all blanks are 0s too
                max_list += ["99"] * (3-len(max_list)) # pad it with 99s for max
                max_list = [x if len(x) else "99" for x in max_list] # Ensure all blanks are 0s too
                temp_min = ".".join(min_list)
                temp_max = ".".join(max_list)
            except: pass # Broken formatting - it seems
        return (temp_min,temp_max)

    def get_min_max_from_kext(self, kext, use_match = False):
        # Helper to get the min/max kernel versions
        if use_match: return self.get_min_max_from_match(kext.get("MatchKernel",""))
        temp_min = kext.get("MinKernel","0.0.0")
        temp_max = kext.get("MaxKernel","99.99.99")
        temp_min = "0.0.0" if temp_min == "" else temp_min
        temp_max = "99.99.99" if temp_max == "" else temp_max
        return (temp_min,temp_max)
    
    def snapshot(self, in_file = None, out_file = None, oc_folder = None, clean = False):
        oc_folder = self.u.check_path(oc_folder)
        if not oc_folder:
            print("OC folder passed does not exist!")
            exit(1)
        if not os.path.isdir(oc_folder):
            print("OC folder passed is not a directory!")
            exit(1)
        if in_file:
            in_file = self.u.check_path(in_file)
            if not in_file:
                print("Input plist passed does not exist!")
                exit(1)
            if os.path.isdir(in_file):
                print("Input plist passed is a directory!")
                exit(1)
            try:
                with open(in_file,"rb") as f:
                    tree_dict = plist.load(f)
            except Exception as e:
                print("Error loading plist: {}".format(e))
                exit(1)
        else:
            if not out_file:
                print("At least one input or output file must be provided.")
                exit(1)
            # We got an out file at least - create an empty dict for the in_file
            tree_dict = {}
        if not out_file: out_file = in_file

        # Verify folder structure - should be as follows:
        # OC
        #  +- ACPI
        #  | +- SSDT.aml
        #  +- Drivers
        #  | +- EfiDriver.efi
        #  +- Kexts
        #  | +- Something.kext
        #  +- config.plist
        #  +- Tools (Optional)
        #  | +- SomeTool.efi
        #  | +- SomeFolder
        #  | | +- SomeOtherTool.efi
        
        oc_acpi    = os.path.join(oc_folder,"ACPI")
        oc_drivers = os.path.join(oc_folder,"Drivers")
        oc_kexts   = os.path.join(oc_folder,"Kexts")
        oc_tools   = os.path.join(oc_folder,"Tools")
        oc_efi     = os.path.join(oc_folder,"OpenCore.efi")

        for x in (oc_acpi,oc_drivers,oc_kexts):
            if not os.path.exists(x):
                print("Incorrect OC Folder Struction - {} does not exist.".format(x))
                exit(1)
            if x != oc_efi and not os.path.isdir(x):
                print("Incorrect OC Folder Struction - {} exists, but is not a directory.".format(x))
                exit(1)

        # Folders are valid - lets work through each section

        # Let's get the hash of OpenCore.efi, compare to a known list, and then compare that version to our snapshot_version if found
        hasher = hashlib.md5()
        try:
            with open(oc_efi,"rb") as f:
                hasher.update(f.read())
            oc_hash = hasher.hexdigest()
        except:
            oc_hash = "" # Couldn't determine hash :(
        # Let's get the version of the snapshot that matches our target, and that matches our hash if any
        latest_snap = {} # Highest min_version
        target_snap = {} # Matches our hash
        for snap in self.snapshot_data:
            hashes = snap.get("release_hashes",[])
            hashes.extend(snap.get("debug_hashes",[]))
            # Retain the highest version we see
            if snap.get("min_version","0.0.0") > latest_snap.get("min_version","0.0.0"):
                latest_snap = snap
            # Also retain the last snap that matches our hash
            if len(oc_hash) and (oc_hash in snap.get("release_hashes",[]) or oc_hash in snap.get("debug_hashes",[])):
                target_snap = snap
        if not target_snap: target_snap = latest_snap
        # Apply our snapshot values
        acpi_add   = target_snap.get("acpi_add",{})
        kext_add   = target_snap.get("kext_add",{})
        tool_add   = target_snap.get("tool_add",{})
        driver_add = target_snap.get("driver_add",{})

        # ACPI is first, we'll iterate the .aml files we have and add what is missing
        # while also removing what exists in the plist and not in the folder.
        # If something exists in the table already, we won't touch it.  This leaves the
        # enabled and comment properties untouched.
        #
        # Let's make sure we have the ACPI -> Add sections in our config

        # We're going to replace the whole list
        if not "ACPI" in tree_dict or not isinstance(tree_dict["ACPI"],dict):
            tree_dict["ACPI"] = {"Add":[]}
        if not "Add" in tree_dict["ACPI"] or not isinstance(tree_dict["ACPI"]["Add"],list):
            tree_dict["ACPI"]["Add"] = []
        # Now we walk the existing add values
        new_acpi = []
        for path, subdirs, files in os.walk(oc_acpi):
            for name in files:
                if not name.startswith(".") and name.lower().endswith(".aml"):
                    new_acpi.append(os.path.join(path,name)[len(oc_acpi):].replace("\\", "/").lstrip("/"))
        add = [] if clean else tree_dict["ACPI"]["Add"]
        for aml in sorted(new_acpi,key=lambda x:x.lower()):
            if aml.lower() in [x.get("Path","").lower() for x in add if isinstance(x,dict)]:
                # Found it - skip
                continue
            # Doesn't exist, add it
            new_aml_entry = {
                "Comment":os.path.basename(aml),
                "Enabled":True,
                "Path":aml
            }
            # Add our snapshot custom entries, if any
            for x in acpi_add: new_aml_entry[x] = acpi_add[x]
            add.append(new_aml_entry)
        new_add = []
        for aml in add:
            if not isinstance(aml,dict):
                # Not the right type - skip it
                continue
            if not aml.get("Path","").lower() in [x.lower() for x in new_acpi]:
                # Not there, skip
                continue
            new_add.append(aml)
        tree_dict["ACPI"]["Add"] = new_add

        # Now we need to walk the kexts
        if not "Kernel" in tree_dict or not isinstance(tree_dict["Kernel"],dict):
            tree_dict["Kernel"] = {"Add":[]}
        if not "Add" in tree_dict["Kernel"] or not isinstance(tree_dict["Kernel"]["Add"],list):
            tree_dict["Kernel"]["Add"] = []

        kext_list = []
        # We need to gather a list of all the files inside that and with .efi
        for path, subdirs, files in os.walk(oc_kexts):
            for name in sorted(subdirs, key=lambda x:x.lower()):
                if name.startswith(".") or not name.lower().endswith(".kext"): continue
                kdict = {
                    # "Arch":"Any",
                    "BundlePath":os.path.join(path,name)[len(oc_kexts):].replace("\\", "/").lstrip("/"),
                    "Comment":name,
                    "Enabled":True,
                    # "MaxKernel":"",
                    # "MinKernel":"",
                    "ExecutablePath":""
                }
                # Add our entries from kext_add as needed
                for y in kext_add: kdict[y] = kext_add[y]
                # Get the Info.plist
                plist_full_path = plist_rel_path = None
                for kpath, ksubdirs, kfiles in os.walk(os.path.join(path,name)):
                    for kname in kfiles:
                        if kname.lower() == "info.plist":
                            plist_full_path = os.path.join(kpath,kname)
                            plist_rel_path = plist_full_path[len(os.path.join(path,name)):].replace("\\", "/").lstrip("/")
                            break
                    if plist_full_path: break # Found it - break
                else:
                    # Didn't find it - skip
                    continue
                kdict["PlistPath"] = plist_rel_path
                # Let's load the plist and check for other info
                try:
                    with open(plist_full_path,"rb") as f:
                        info_plist = plist.load(f)
                    kinfo = {
                        "CFBundleIdentifier": info_plist.get("CFBundleIdentifier",None),
                        "OSBundleLibraries": info_plist.get("OSBundleLibraries",[])
                    }
                    if info_plist.get("CFBundleExecutable",None):
                        if not os.path.exists(os.path.join(path,name,"Contents","MacOS",info_plist["CFBundleExecutable"])):
                            continue # Requires an executable that doesn't exist - bail
                        kdict["ExecutablePath"] = "Contents/MacOS/"+info_plist["CFBundleExecutable"]
                except Exception as e: 
                    continue # Something else broke here - bail
                # Should have something valid here
                kext_list.append((kdict,kinfo))

        bundle_list = [x[0].get("BundlePath","") for x in kext_list]
        kexts = [] if clean else tree_dict["Kernel"]["Add"]
        original_kexts = [x for x in kexts if x.get("BundlePath","") in bundle_list] # get the original load order for comparison purposes - but omit any that no longer exist
        for kext,info in kext_list:
            if kext["BundlePath"].lower() in [x.get("BundlePath","").lower() for x in kexts if isinstance(x,dict)]:
                # Already have it, skip
                continue
            # We need it, it seems
            kexts.append(kext)
        new_kexts = []
        for kext in kexts:
            if not isinstance(kext,dict):
                # Not a dict - skip it
                continue
            if not kext.get("BundlePath","").lower() in [x[0]["BundlePath"].lower() for x in kext_list]:
                # Not there, skip it
                continue
            new_kexts.append(kext)
        # Let's check inheritance via the info
        # We need to ensure that no 2 kexts consider each other as parents
        unordered_kexts = []
        for x in new_kexts:
            x = next((y for y in kext_list if y[0].get("BundlePath","") == x.get("BundlePath","")),None)
            if not x: continue
            parents = [next((z for z in new_kexts if z.get("BundlePath","") == y[0].get("BundlePath","")),[]) for y in kext_list if y[1].get("CFBundleIdentifier",None) in x[1].get("OSBundleLibraries",[])]
            children = [next((z for z in new_kexts if z.get("BundlePath","") == y[0].get("BundlePath","")),[]) for y in kext_list if x[1].get("CFBundleIdentifier",None) in y[1].get("OSBundleLibraries",[])]
            parents = [y for y in parents if not y in children and not y.get("BundlePath","") == x[0].get("BundlePath","")]
            unordered_kexts.append({
                "kext":x[0],
                "parents":parents
            })
        ordered_kexts = []
        disabled_parents = []
        while len(unordered_kexts): # This could be dangerous if things aren't properly prepared above
            kext = unordered_kexts.pop(0)
            if len(kext["parents"]):
                disabled_parents.extend([x.get("BundlePath","") for x in kext["parents"] if x.get("Enabled",True) == False and not x.get("BundlePath","") in disabled_parents])
                if not all(x in ordered_kexts for x in kext["parents"]):
                    unordered_kexts.append(kext)
                    continue
            ordered_kexts.append(next(x for x in new_kexts if x.get("BundlePath","") == kext["kext"].get("BundlePath","")))
        # Let's compare against the original load order - to prevent mis-prompting
        missing_kexts = [x for x in ordered_kexts if not x in original_kexts]
        original_kexts.extend(missing_kexts)
        # Let's walk both lists and gather all kexts that are in different spots
        rearranged = []
        while True:
            check1 = [x.get("BundlePath","") for x in ordered_kexts if not x.get("BundlePath","") in rearranged]
            check2 = [x.get("BundlePath","") for x in original_kexts if not x.get("BundlePath","") in rearranged]
            out_of_place = next((x for x in range(len(check1)) if check1[x] != check2[x]),None)
            if out_of_place == None: break
            rearranged.append(check2[out_of_place])
        # Verify if the load order changed - and prompt the user if need be
        if len(rearranged):
            print("Incorrect kext load order has been corrected:\n\n{}".format("\n".join(rearranged)))
            ordered_kexts = original_kexts # We didn't want to update it
        if len(disabled_parents):
            print("Disabled parent kexts have been enabled:\n\n{}".format("\n".join(disabled_parents)))
            for x in ordered_kexts: # Walk our kexts and enable the parents
                if x.get("BundlePath","") in disabled_parents: x["Enabled"] = True
        # Finally - we walk the kexts and ensure that we're not loading the same CFBundleIdentifier more than once
        enabled_kexts = []
        duplicate_bundles = []
        duplicates_disabled = []
        for kext in ordered_kexts:
            temp_kext = {}
            # Shallow copy the kext entry to avoid changing it in ordered_kexts
            for x in kext: temp_kext[x] = kext[x]
            duplicates_disabled.append(temp_kext)
            # Ignore if alreday disabled
            if not temp_kext.get("Enabled",False): continue
            # Get the original info
            info = next((x for x in kext_list if x[0].get("BundlePath","") == temp_kext.get("BundlePath","")),None)
            if not info or not info[1].get("CFBundleIdentifier",None): continue # Broken info
            # Let's see if it's already in enabled_kexts - and compare the Min/Max/Match Kernel options
            temp_min,temp_max = self.get_min_max_from_kext(temp_kext,"MatchKernel" in kext_add)
            # Gather a list of like IDs
            comp_kexts = [x for x in enabled_kexts if x[1]["CFBundleIdentifier"] == info[1]["CFBundleIdentifier"]]
            # Walk the comp_kexts, and disable if we find an overlap
            for comp_info in comp_kexts:
                comp_kext = comp_info[0]
                # Gather our min/max
                comp_min,comp_max = self.get_min_max_from_kext(comp_kext,"MatchKernel" in kext_add)
                # Let's see if we don't overlap
                if temp_min > comp_max or temp_max < comp_min: # We're good, continue
                    continue
                # We overlapped - let's disable it
                temp_kext["Enabled"] = False
                # Add it to the list - then break out of this loop
                duplicate_bundles.append(temp_kext.get("BundlePath",""))
                break
            # Check if we ended up disabling temp_kext, and if not - add it to the enabled_kexts list
            if temp_kext.get("Enabled",False): enabled_kexts.append((temp_kext,info[1]))
        # Check if we have duplicates - and offer to disable them
        if len(duplicate_bundles):
            print("Duplicate CFBundleIdentifiers have been disabled:\n\n{}".format("\n".join(duplicate_bundles)))
            ordered_kexts = duplicates_disabled

        tree_dict["Kernel"]["Add"] = ordered_kexts

        # Let's walk the Tools folder if it exists
        if not "Misc" in tree_dict or not isinstance(tree_dict["Misc"],dict):
            tree_dict["Misc"] = {"Tools":[]}
        if not "Tools" in tree_dict["Misc"] or not isinstance(tree_dict["Misc"]["Tools"],list):
            tree_dict["Misc"]["Tools"] = []
        if os.path.exists(oc_tools) and os.path.isdir(oc_tools):
            tools_list = []
            # We need to gather a list of all the files inside that and with .efi
            for path, subdirs, files in os.walk(oc_tools):
                for name in files:
                    if not name.startswith(".") and name.lower().endswith(".efi"):
                        # Save it
                        new_tool_entry = {
                            # "Arguments":"",
                            # "Auxiliary":True,
                            "Name":name,
                            "Comment":name,
                            "Enabled":True,
                            "Path":os.path.join(path,name)[len(oc_tools):].replace("\\", "/").lstrip("/") # Strip the /Volumes/EFI/
                        }
                        # Add our snapshot custom entries, if any
                        for x in tool_add: new_tool_entry[x] = tool_add[x]
                        tools_list.append(new_tool_entry)
            tools = [] if clean else tree_dict["Misc"]["Tools"]
            for tool in sorted(tools_list, key=lambda x: x.get("Path","").lower()):
                if tool["Path"].lower() in [x.get("Path","").lower() for x in tools if isinstance(x,dict)]:
                    # Already have it, skip
                    continue
                # We need it, it seems
                tools.append(tool)
            new_tools = []
            for tool in tools:
                if not isinstance(tool,dict):
                    # Not a dict - skip it
                    continue
                if not tool.get("Path","").lower() in [x["Path"].lower() for x in tools_list]:
                    # Not there, skip it
                    continue
                new_tools.append(tool)
            tree_dict["Misc"]["Tools"] = new_tools
        else:
            # Make sure our Tools list is empty
            tree_dict["Misc"]["Tools"] = []

        # Last we need to walk the .efi drivers
        if not "UEFI" in tree_dict or not isinstance(tree_dict["UEFI"],dict):
            tree_dict["UEFI"] = {"Drivers":[]}
        if not "Drivers" in tree_dict["UEFI"] or not isinstance(tree_dict["UEFI"]["Drivers"],list):
            tree_dict["UEFI"]["Drivers"] = []
        if os.path.exists(oc_drivers) and os.path.isdir(oc_drivers):
            drivers_list = []
            # We need to gather a list of all the files inside that and with .efi
            for path, subdirs, files in os.walk(oc_drivers):
                for name in files:
                    if not name.startswith(".") and name.lower().endswith(".efi"):
                        # Check if we're using the new approach - or just listing the paths
                        if not driver_add:
                            drivers_list.append(os.path.join(path,name)[len(oc_drivers):].replace("\\", "/").lstrip("/")) # Strip the /Volumes/EFI/
                        else:
                            new_driver_entry = {
                                # "Arguments": "",
                                "Enabled":True,
                                "Path":os.path.join(path,name)[len(oc_drivers):].replace("\\", "/").lstrip("/") # Strip the /Volumes/EFI/
                            }
                            # Add our snapshot custom entries, if any
                            for x in driver_add: new_driver_entry[x] = name if x.lower() == "comment" else driver_add[x]
                            drivers_list.append(new_driver_entry)
            drivers = [] if clean else tree_dict["UEFI"]["Drivers"]
            for driver in sorted(drivers_list, key=lambda x: x.get("Path","").lower() if driver_add else x):
                if not driver_add: # Old way
                    if not isinstance(driver,(str,unicode)) or driver.lower() in [x.lower() for x in drivers if isinstance(x,(str,unicode))]:
                        continue
                else:
                    if driver["Path"].lower() in [x.get("Path","").lower() for x in drivers if isinstance(x,dict)]:
                        # Already have it, skip
                        continue
                # We need it, it seems
                drivers.append(driver)
            new_drivers = []
            for driver in drivers:
                if not driver_add: # Old way
                    if not isinstance(driver,(str,unicode)) or not driver.lower() in [x.lower() for x in drivers_list if isinstance(x,(str,unicode))]:
                        continue
                else:
                    if not isinstance(driver,dict):
                        # Not a dict - skip it
                        continue
                    if not driver.get("Path","").lower() in [x["Path"].lower() for x in drivers_list]:
                        # Not there, skip it
                        continue
                new_drivers.append(driver)
            tree_dict["UEFI"]["Drivers"] = new_drivers
        else:
            # Make sure our Drivers list is empty
            tree_dict["UEFI"]["Drivers"] = []
        
        try:
            with open(out_file, "wb") as f:
                plist.dump(tree_dict,f)
            print("\nOutput saved to: {}".format(out_file))
        except Exception as e:
            print("Failed to write output plist: {}".format(e))
            exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input-file", help="Path to the input plist - will use an empty dictionary if none passed.")
    parser.add_argument("-o", "--output-file", help="Path to the output plist if different than input.")
    parser.add_argument("-s", "--snapshot", help="Path to the OC folder to snapshot.")
    parser.add_argument("-c", "--clean-snapshot", help="Remove existing ACPI, Kernel, Driver, and Tool entries before adding anew.", action="store_true")
    args = parser.parse_args()
    if not args.snapshot or (not args.input_file and not args.output_file):
        print("Missing at least one required argument!\n")
        if not args.snapshot: print("-s/--snapshot is a required argument!")
        if (not args.input_file and not args.output_file): print("At least one -i/--input-file or -o/--output-file must be provided!")
        print("")
        parser.print_help()
        exit(1)
    o = OCSnapshot()
    o.snapshot(args.input_file, args.output_file, args.snapshot, args.clean_snapshot)
