# Crypto++ Library Documentation Guide
Note: see at <https://www.cryptopp.com/> or build in local pc
This guide provides step-by-step instructions on how to generate documentation for the Crypto++ Library using Doxygen. It is designed for projects where documentation is derived primarily from header and class code files.

## Prerequisites

- **Doxygen**: Ensure Doxygen is installed on your system. For example, if you're using pacman on Windows:

  ```bash
  pacman -S mingw-w64-x86_64-doxygen
  ```

- **Crypto++ Library Source**: Make sure you have the Crypto++ source code available on your system.

## Steps to Generate Documentation

### 1. Install Doxygen

Install Doxygen if you haven't already. On systems using pacman, you can install it with:

```bash
pacman -S mingw-w64-x86_64-doxygen
```

### 2. Create a Default Configuration File

Generate a default configuration file by running:

```bash
doxygen -g cryptoppguides
```

This command creates a default configuration file (named `cryptoppguides` or `cryptoppguides.conf`).

### 3. Edit the Configuration File

Open the configuration file in your favorite text editor and update the following parameters:

- **Project Name**: Set the project name.

  ```ini
  PROJECT_NAME = "Crypto++ Library"
  ```

- **Input Directory**: Specify the directory where the Crypto++ source files are located.

  ```ini
  INPUT = /path/to/cryptopp
  # Example:
  INPUT = "D:/Labs_Crypto/NT219-2025/cryptopp890"
  ```

- **Output Directory**: Set the directory where the generated documentation will be saved.

  ```ini
  OUTPUT_DIRECTORY = /path/to/output/docs
  # Example:
  OUTPUT_DIRECTORY = "D:/Labs_Crypto/NT219-2025/cryptoguides"
  ```

- **Documentation Format**: Configure the output format and recursion settings.

  ```ini
  GENERATE_LATEX = NO
  GENERATE_HTML  = YES
  RECURSIVE      = YES
  ```

### 4. Generate the Documentation

Once the configuration file is set up, run the following command to generate the documentation:

```bash
doxygen cryptoppguides
```

This command processes the source files and creates HTML documentation in the specified output directory.

## Additional Notes

- **Header and Class Files**: The guide focuses on generating documentation from header and class files, ensuring that your class structures and code comments are properly documented.
- **Customization**: You can further customize the Doxygen configuration file to suit your project’s needs. For more advanced options, refer to the [Doxygen Manual](http://www.doxygen.nl/manual/index.html).

## Conclusion

By following these steps, you will generate comprehensive documentation for the Crypto++ Library. Adjust the configuration as necessary to match your project's structure and documentation requirements.
