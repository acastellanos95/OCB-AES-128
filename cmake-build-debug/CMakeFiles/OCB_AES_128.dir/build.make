# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/OCB_AES_128.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/OCB_AES_128.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/OCB_AES_128.dir/flags.make

CMakeFiles/OCB_AES_128.dir/main.c.o: CMakeFiles/OCB_AES_128.dir/flags.make
CMakeFiles/OCB_AES_128.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/OCB_AES_128.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/OCB_AES_128.dir/main.c.o   -c /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/main.c

CMakeFiles/OCB_AES_128.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/OCB_AES_128.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/main.c > CMakeFiles/OCB_AES_128.dir/main.c.i

CMakeFiles/OCB_AES_128.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/OCB_AES_128.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/main.c -o CMakeFiles/OCB_AES_128.dir/main.c.s

# Object files for target OCB_AES_128
OCB_AES_128_OBJECTS = \
"CMakeFiles/OCB_AES_128.dir/main.c.o"

# External object files for target OCB_AES_128
OCB_AES_128_EXTERNAL_OBJECTS =

OCB_AES_128: CMakeFiles/OCB_AES_128.dir/main.c.o
OCB_AES_128: CMakeFiles/OCB_AES_128.dir/build.make
OCB_AES_128: CMakeFiles/OCB_AES_128.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable OCB_AES_128"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/OCB_AES_128.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/OCB_AES_128.dir/build: OCB_AES_128

.PHONY : CMakeFiles/OCB_AES_128.dir/build

CMakeFiles/OCB_AES_128.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/OCB_AES_128.dir/cmake_clean.cmake
.PHONY : CMakeFiles/OCB_AES_128.dir/clean

CMakeFiles/OCB_AES_128.dir/depend:
	cd /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128 /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128 /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/cmake-build-debug /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/cmake-build-debug /mnt/c/Users/andre/Documents/GitHub/OCB-AES-128/cmake-build-debug/CMakeFiles/OCB_AES_128.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/OCB_AES_128.dir/depend

