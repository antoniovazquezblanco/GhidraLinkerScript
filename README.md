# Ghidra Linker Script

[![Build](https://github.com/antoniovazquezblanco/GhidraLinkerScript/actions/workflows/main.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraLinkerScript/actions/workflows/main.yml)
[![CodeQL](https://github.com/antoniovazquezblanco/GhidraLinkerScript/actions/workflows/codeql.yml/badge.svg)](https://github.com/antoniovazquezblanco/GhidraLinkerScript/actions/workflows/codeql.yml)

<p align="center">
  <img width="400" src="doc/logo.png" alt="A medieval dragon holding a book with linker script writings">
</p>

This is a Ghidra extension that provides some user friendly ways to parse small source code snippets into data types.

## Installing

This extension is available for installation via the [Ghidra Extension Manager](https://github.com/antoniovazquezblanco/GhidraExtensionManager).

You may also install this extension by going to the [releases page](https://github.com/antoniovazquezblanco/GhidraLinkerScript/releases) and downloading the latest version for your Ghidra distribution. In order to install from the release, in Ghidra main window go to `File` > `Install extensions...`. In the new window press the `+` icon to import the downloaded zip.

## Using

In a CodeBrowser window press `File` > `Import LD Script...`.

A file dialog will allow you to select your LD Script file and import symbol information from it.

## Develop

For development instructions checkout [doc/Develop.md](doc/Develop.md).
