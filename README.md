# Copy as XMLHttpRequest BurpSuite extension

The extension adds a context menu to BurpSuite that allows you to copy multiple requests as Javascript's XmlHttpRequest, which simplifies PoC development when exploiting XSS.

![demo](https://user-images.githubusercontent.com/24279065/112390476-71e43200-8d07-11eb-90da-797d829c3e3e.mp4)

## Installation

- download the latest JAR from releases or build manually
- add JAR to burpsuite using tabs: "Extender" -> "Extensions" -> "Add"

## Usage

- select one request from any tab or a few requests in "Proxy" -> "HTTP history" tab
- invoke context menu and select "Copy as XMLHttpRequest"
