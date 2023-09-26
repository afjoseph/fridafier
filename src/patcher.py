from loguru import logger
import os
import subprocess
import glob
import shutil
import sys
import tempfile
import time
import typing as t

ARCH_ARM = "arm"
ARCH_ARM64 = "arm64"
ARCH_X86 = "x86"
ARCH_X64 = "x64"
DEFAULT_GADGET_NAME = "libfrida-gadget.so"
DEFAULT_CONFIG_NAME = "libfrida-gadget.config.so"
DEFAULT_HOOKFILE_NAME = "libhook.js.so"
CONFIG_BIT = 1 << 0
AUTOLOAD_BIT = 1 << 1


def get_recommended_gadget() -> t.Optional[str]:
    ret = None

    logger.debug("Trying to identify the right frida-gadget...")
    logger.debug("Waiting for device...")
    os.system("adb wait-for-device")
    abi = (
        subprocess.check_output(["adb", "shell", "getprop ro.product.cpu.abi"])
        .decode("utf-8")
        .strip()
    )

    logger.debug("The abi is {0}".format(abi))

    frida_version = (
        subprocess.check_output(["frida", "--version"]).strip().decode("utf-8")
    )
    current_folder = os.path.dirname(os.path.abspath(__file__))
    gadgets_folder = os.path.join(current_folder, "gadgets")
    target_folder = os.path.join(gadgets_folder, frida_version)

    if os.path.isdir(target_folder):
        dir_list = os.listdir(target_folder)
        gadget_files = [
            f for f in dir_list if os.path.isfile(os.path.join(target_folder, f))
        ]
    else:
        logger.error(
            'Gadget folder not found. Try "python {0} --update-gadgets"'.format(
                sys.argv[0]
            )
        )
        return None

    if abi in ["armeabi", "armeabi-v7a"]:
        for gadget_file in gadget_files:
            if "arm" in gadget_file and "64" not in gadget_file:
                full_path = os.path.join(target_folder, gadget_file)
                ret = full_path
                break

    elif abi == "arm64-v8a" or "arm64" in abi:
        for gadget_file in gadget_files:
            if "arm64" in gadget_file:
                full_path = os.path.join(target_folder, gadget_file)
                ret = full_path
                break

    elif abi == "x86":
        for gadget_file in gadget_files:
            if "i386" in gadget_file:
                full_path = os.path.join(target_folder, gadget_file)
                ret = full_path
                break

    elif abi == "x86_64":
        for gadget_file in gadget_files:
            if "x86_64" in gadget_file:
                full_path = os.path.join(target_folder, gadget_file)
                ret = full_path
                break

    return ret


def extract_apk(apk_path, destination_path, extract_resources=True):
    if extract_resources:
        logger.debug(
            "Extracting {0} (with resources) to {1}".format(apk_path, destination_path)
        )

        subprocess.check_output(
            ["apktool", "-f", "d", "-o", destination_path, apk_path]
        )
    else:
        logger.debug(
            "Extracting {0} (without resources) to {1}".format(
                apk_path, destination_path
            )
        )
        subprocess.check_output(
            ["apktool", "-f", "-r", "d", "-o", destination_path, apk_path]
        )


def get_entrypoint_class_name(apk_path) -> t.Optional[str]:
    dump_lines = (
        subprocess.check_output(["aapt", "dump", "badging", apk_path])
        .decode("utf-8")
        .split("\n")
    )
    entrypoint_class = None

    for line in dump_lines:
        if "launchable-activity:" in line:
            name_start = line.find("name=")
            entrypoint_class = (
                line[name_start:]
                .split(" ")[0]
                .replace("name=", "")
                .replace("'", "")
                .replace('"', "")
            )

            break

    return entrypoint_class


def get_entrypoint_smali_path(base_path, entrypoint_class) -> t.Optional[str]:
    files_at_path = os.listdir(base_path)
    entrypoint_final_path = None

    for file in files_at_path:
        if file.startswith("smali"):
            entrypoint_tmp = os.path.join(
                base_path, file, entrypoint_class.replace(".", "/") + ".smali"
            )

            if os.path.isfile(entrypoint_tmp):
                entrypoint_final_path = entrypoint_tmp
                break

    return entrypoint_final_path


def create_temp_folder_for_apk(apk_path):
    system_tmp_dir = tempfile.gettempdir()
    tmp_dir = os.path.join(system_tmp_dir, "apkptmp")

    apk_name = apk_path.split("/")[-1]

    final_tmp_dir = os.path.join(
        tmp_dir, apk_name.replace(".apk", "").replace(".", "_")
    )

    if os.path.isdir(final_tmp_dir):
        logger.debug("App temp dir already exists. Removing it...")
        shutil.rmtree(final_tmp_dir)

    os.makedirs(final_tmp_dir)

    return final_tmp_dir


def insert_frida_loader(entrypoint_smali_path, frida_lib_name="frida-gadget"):
    partial_injection_code = """
const-string v0, "<LIBFRIDA>"

invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    """.replace(
        "<LIBFRIDA>", frida_lib_name
    )

    full_injection_code = """
.method static constructor <clinit>()V
.locals 1

.prologue
const-string v0, "<LIBFRIDA>"

invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

return-void
.end method
    """.replace(
        "<LIBFRIDA>", frida_lib_name
    )

    with open(entrypoint_smali_path, "r") as smali_file:
        content = smali_file.read()

        if "frida-gadget" in content:
            logger.debug("The frida-gadget is already in the entrypoint. Skipping...")
            return False

        direct_methods_start_index = content.find("# direct methods")
        direct_methods_end_index = content.find("# virtual methods")

        if direct_methods_start_index == -1 or direct_methods_end_index == -1:
            raise Exception("Could not find direct methods")

        class_constructor_start_index = content.find(
            ".method static constructor <clinit>()V",
            direct_methods_start_index,
            direct_methods_end_index,
        )

        if class_constructor_start_index == -1:
            has_class_constructor = False
        else:
            has_class_constructor = True

        class_constructor_end_index = -1
        if has_class_constructor:
            class_constructor_end_index = content.find(
                ".end method",
                class_constructor_start_index,
                direct_methods_end_index,
            )

        if has_class_constructor and class_constructor_end_index == -1:
            raise Exception("Could not find the end of class constructor")

        prologue_start_index = -1
        if has_class_constructor:
            prologue_start_index = content.find(
                ".prologue",
                class_constructor_start_index,
                class_constructor_end_index,
            )

        no_prologue_case = False
        locals_start_index = -1
        if has_class_constructor and prologue_start_index == -1:
            no_prologue_case = True

            locals_start_index = content.find(
                ".locals ",
                class_constructor_start_index,
                class_constructor_end_index,
            )

        if no_prologue_case and locals_start_index == -1:
            raise Exception(
                'Has class constructor. No prologue case, but no "locals 0" found.'
            )

        locals_end_index = -1
        if no_prologue_case:
            locals_end_index = locals_start_index + len("locals X")

        prologue_end_index = -1
        if has_class_constructor and prologue_start_index > -1:
            prologue_end_index = prologue_start_index + len(".prologue") + 1

        if has_class_constructor:
            if no_prologue_case:
                new_content = content[0:locals_end_index]

                if content[locals_end_index] == "0":
                    new_content += "1"
                else:
                    new_content += content[locals_end_index]

                new_content += "\n\n    .prologue"
                new_content += partial_injection_code
                new_content += content[locals_end_index + 1 :]
            else:
                new_content = content[0:prologue_end_index]
                new_content += partial_injection_code
                new_content += content[prologue_end_index:]
        else:
            tmp_index = direct_methods_start_index + len("# direct methods") + 1
            new_content = content[0:tmp_index]
            new_content += full_injection_code
            new_content += content[tmp_index:]

    # The newContent is ready to be saved

    with open(entrypoint_smali_path, "w") as smali_file:
        smali_file.write(new_content)

    logger.debug("Frida loader was injected in the entrypoint smali file!")

    return True


def get_arch_by_gadget(gadget_path):
    if "arm" in gadget_path and "64" not in gadget_path:
        return ARCH_ARM

    elif "arm64" in gadget_path:
        return ARCH_ARM64

    elif "i386" in gadget_path or ("x86" in gadget_path and "64" not in gadget_path):
        return ARCH_X86

    elif "x86_64" in gadget_path:
        return ARCH_X64

    else:
        return None


def create_lib_arch_folders(base_path, arch):
    sub_dir = None
    sub_dir_2 = ""

    libs_path = os.path.join(base_path, "lib/")

    if not os.path.isdir(libs_path):
        logger.debug('There is no "lib" folder. Creating...')
        os.makedirs(libs_path)

    if arch == ARCH_ARM:
        sub_dir = os.path.join(libs_path, "armeabi")
        sub_dir_2 = os.path.join(libs_path, "armeabi-v7a")

    elif arch == ARCH_ARM64:
        sub_dir = os.path.join(libs_path, "arm64-v8a")

    elif arch == ARCH_X86:
        sub_dir = os.path.join(libs_path, "x86")

    elif arch == ARCH_X64:
        sub_dir = os.path.join(libs_path, "x86_64")

    else:
        raise Exception("Couldn't create the appropriate folder with the given arch.")

    if not os.path.isdir(sub_dir):
        logger.debug("Creating folder {0}".format(sub_dir))
        os.makedirs(sub_dir)

    if arch == ARCH_ARM:
        if not os.path.isdir(sub_dir_2):
            logger.debug("Creating folder {0}".format(sub_dir_2))
            os.makedirs(sub_dir_2)

    if arch == ARCH_ARM:
        return [sub_dir, sub_dir_2]

    else:
        return [sub_dir]


def delete_existing_gadget(arch_folder, delete_custom_files=0):
    gadget_path = os.path.join(arch_folder, DEFAULT_GADGET_NAME)

    if os.path.isfile(gadget_path):
        os.remove(gadget_path)

    if delete_custom_files & CONFIG_BIT:
        config_file_path = os.path.join(arch_folder, DEFAULT_CONFIG_NAME)

        if os.path.isfile(config_file_path):
            os.remove(config_file_path)

    if delete_custom_files & AUTOLOAD_BIT:
        hookfile_path = os.path.join(arch_folder, DEFAULT_HOOKFILE_NAME)

        if os.path.isfile(hookfile_path):
            os.remove(hookfile_path)


def insert_frida_lib(
    base_path, gadget_path, config_file_path=None, auto_load_script_path=None
):
    arch = get_arch_by_gadget(gadget_path)
    arch_folders = create_lib_arch_folders(base_path, arch)

    if not arch_folders:
        raise Exception("Some error occurred while creating the libs folders")

    for folder in arch_folders:
        if config_file_path and auto_load_script_path:
            delete_existing_gadget(
                folder, delete_custom_files=CONFIG_BIT | AUTOLOAD_BIT
            )

        elif config_file_path and not auto_load_script_path:
            delete_existing_gadget(folder, delete_custom_files=CONFIG_BIT)

        elif auto_load_script_path and not config_file_path:
            delete_existing_gadget(folder, delete_custom_files=AUTOLOAD_BIT)

        else:
            delete_existing_gadget(folder, delete_custom_files=0)

        target_gadget_path = os.path.join(folder, DEFAULT_GADGET_NAME)

        logger.debug("Copying gadget to {0}".format(target_gadget_path))

        shutil.copyfile(gadget_path, target_gadget_path)

        if config_file_path:
            target_config_path = target_gadget_path.replace(".so", ".config.so")

            logger.debug("Copying config file to {0}".format(target_config_path))
            shutil.copyfile(config_file_path, target_config_path)

        if auto_load_script_path:
            target_autoload_path = target_gadget_path.replace(
                DEFAULT_GADGET_NAME, DEFAULT_HOOKFILE_NAME
            )

            logger.debug(
                "Copying auto load script file to {0}".format(target_autoload_path)
            )
            shutil.copyfile(auto_load_script_path, target_autoload_path)

    return True


def repackage_apk(base_apk_path, apk_name, target_file=None, use_aapt2=False):
    if target_file is None:
        current_path = os.getcwd()
        target_file = os.path.join(
            current_path, apk_name.replace(".apk", "_patched.apk")
        )

        if os.path.isfile(target_file):
            timestamp = str(time.time()).replace(".", "")
            new_file_name = target_file.replace(".apk", "_{0}.apk".format(timestamp))
            target_file = new_file_name

    logger.debug("Repackaging apk to {0}".format(target_file))

    apktool_build_cmd = ["apktool", "b", "-o", target_file, base_apk_path]
    if use_aapt2:
        apktool_build_cmd.insert(1, "--use-aapt2")  # apktool --use-aapt2 b ...

    subprocess.check_output(apktool_build_cmd)

    return target_file


def sign(
    apk_path: str,
    uber_apk_signer_path: str,
    temp_path: str,
):
    logger.debug("Signing the patched apk...")
    subprocess.check_call(
        ["java", "-jar", uber_apk_signer_path, "-a", apk_path, "-o", temp_path]
    )
    t = glob.glob(os.path.join(temp_path, "*.apk"))
    if len(t) != 1:
        raise Exception("Failed to sign the apk")
    shutil.move(t[0], apk_path)
    logger.debug("The file was optimized: {0}".format(apk_path))


@staticmethod
def get_int_frida_version(str_version):
    version_split = str_version.split(".")
    if len(version_split) > 3:
        version_split = version_split[0:3]
    while len(version_split) < 3:
        version_split.append("0")
    return int("".join(["{num:03d}".format(num=int(i)) for i in version_split]))


@staticmethod
def get_default_config_file():
    config = """{
    "interaction": {
        "type": "script",
        "address": "127.0.0.1",
        "port": 27042,
        "path": "./libhook.js.so"
    }
}
"""

    path = os.path.join(os.getcwd(), "frida.config")
    f = open(path, "w")
    f.write(config)
    f.close()
    return path
