# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.15.2/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.15.2/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/nprice/Projects/tp27v2/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/nprice/Projects/tp27v2/src

# Include any dependencies generated for this target.
include esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/depend.make

# Include the progress variables for this target.
include esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/progress.make

# Include the compile flags for this target's objects.
include esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/flags.make

esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/esp_rom.c.obj: esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/flags.make
esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/esp_rom.c.obj: /Users/nprice/Projects/esp-idf/components/esp_rom/esp_rom.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/nprice/Projects/tp27v2/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/esp_rom.c.obj"
	cd /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom && /Users/nprice/.espressif/tools/xtensa-esp32-elf/esp32-2019r1-8.2.0/xtensa-esp32-elf/bin/xtensa-esp32-elf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/__idf_esp_rom.dir/esp_rom.c.obj   -c /Users/nprice/Projects/esp-idf/components/esp_rom/esp_rom.c

esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/esp_rom.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/__idf_esp_rom.dir/esp_rom.c.i"
	cd /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom && /Users/nprice/.espressif/tools/xtensa-esp32-elf/esp32-2019r1-8.2.0/xtensa-esp32-elf/bin/xtensa-esp32-elf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/nprice/Projects/esp-idf/components/esp_rom/esp_rom.c > CMakeFiles/__idf_esp_rom.dir/esp_rom.c.i

esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/esp_rom.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/__idf_esp_rom.dir/esp_rom.c.s"
	cd /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom && /Users/nprice/.espressif/tools/xtensa-esp32-elf/esp32-2019r1-8.2.0/xtensa-esp32-elf/bin/xtensa-esp32-elf-gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/nprice/Projects/esp-idf/components/esp_rom/esp_rom.c -o CMakeFiles/__idf_esp_rom.dir/esp_rom.c.s

# Object files for target __idf_esp_rom
__idf_esp_rom_OBJECTS = \
"CMakeFiles/__idf_esp_rom.dir/esp_rom.c.obj"

# External object files for target __idf_esp_rom
__idf_esp_rom_EXTERNAL_OBJECTS =

esp-idf/esp_rom/libesp_rom.a: esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/esp_rom.c.obj
esp-idf/esp_rom/libesp_rom.a: esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/build.make
esp-idf/esp_rom/libesp_rom.a: esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/nprice/Projects/tp27v2/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libesp_rom.a"
	cd /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom && $(CMAKE_COMMAND) -P CMakeFiles/__idf_esp_rom.dir/cmake_clean_target.cmake
	cd /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/__idf_esp_rom.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/build: esp-idf/esp_rom/libesp_rom.a

.PHONY : esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/build

esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/clean:
	cd /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom && $(CMAKE_COMMAND) -P CMakeFiles/__idf_esp_rom.dir/cmake_clean.cmake
.PHONY : esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/clean

esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/depend:
	cd /Users/nprice/Projects/tp27v2/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/nprice/Projects/tp27v2/src /Users/nprice/Projects/esp-idf/components/esp_rom /Users/nprice/Projects/tp27v2/src /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom /Users/nprice/Projects/tp27v2/src/esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : esp-idf/esp_rom/CMakeFiles/__idf_esp_rom.dir/depend

