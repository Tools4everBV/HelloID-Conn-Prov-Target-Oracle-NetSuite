
# HelloID-Conn-Prov-Target-Oracle-Netsuite



| :information_source: information                                                                                             |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

<p align="center">
  <img src="https://encrypted-tbn2.gstatic.com/images?q=tbn:ANd9GcTaqK34Oey017kx7Fs31pGy0gkSOUSOIzPvB4d0d1ki2c0wmRnJ">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Oracle-Netsuite](#helloid-conn-prov-target-oracle-netsuite)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Connection settings](#connection-settings)
    - [Prerequisites](#prerequisites)
    - [Remarks](#remarks)
        - [User Account Create](#user-account-create)
      - [Creation / correlation process](#creation--correlation-process)
      - [Correlation](#correlation)
  - [Setup the connector](#setup-the-connector)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Oracle-Netsuite_ is a _target_ connector. Oracle-Netsuite provides a set of REST API's that allow you to programmatically interact with its data. The connector support Employee and Account Management. Authorization/Roles are out of scope.

## Getting started


### Connection settings

The following settings are required to connect to the API.

| Setting        | Description                              | Mandatory |
| -------------- | ---------------------------------------- | --------- |
| ConsumerKey    | The ConsumerKey to connect to the API    | Yes       |
| ConsumerSecret | The ConsumerSecret to connect to the API | Yes       |
| AccessToken    | The AccessToken to connect to the API    | Yes       |
| TokenSecret    | The TokenSecret to connect to the API    | Yes       |
| Realm          | The Realm to connect to the API          | Yes       |
| BaseUrl        | The URL to the API                       | Yes       |

### Prerequisites
 - Access to the API (Connection Settings available)
 - A mapping file or a Source mapping property for the department in NetSuite. *(The connector preforms a Lookup on the Department name to gather the Department id.)*  **(Requires Access to read Departments: ```department?q=name is Algemeen```)**
 - A CustomForm (id) to create employees *(Hardcoded property in account object)*
 - A subsidiary (id) (DochterOnderneming) to create employees *(Hardcoded property in account object)*
 -



### Remarks
- All update actions returning just a status code 204. This behavior requires an extra call in the create.ps1 to get the created Employee after its creation to gather the AccountRefernece.
- The supervisor (manager) in NetSuite must be added to a user by the account Reference of the manager. For this, the mRef in HelloId is used.

##### User Account Create
- The user account Connector only contains two script a Create and Update. *(Can be found in de UserConnector folder)*
- Relies on the Account reference, provided by the Employee Connector in the Export Data.
- Some properties are required to create a user account, like a password and a role.
- The current implementation is as follows. There is a hard-coded role assigned to the employee. And an email is sent to the newly created user account.
- For more information about the properties please [Check the vendor Documentation](https://system.netsuite.com/help/helpcenter/en_US/APIs/REST_API_Browser/record/v1/2022.1/index.html#/definitions/employee).
- The Role and password properties will be skipped if a person does have already an existing account in Netsuite.

```powerhell
$account = @{
    giveAccess       = $true
    requirePwdChange = $true
    sendEmail        = $true
    roles            = @{
        items = @(
            @{
                selectedRole = @{
                    id = 1  # Id of the Role
                }
            }
        )
    }
}
```

#### Creation / correlation process

A new functionality is the possibility to update the account in the target system during the correlation process. By default, this behavior is disabled. Meaning, the account will only be created or correlated.

You can change this behavior in the `create.ps1` by setting the boolean `$updatePerson` to the value of `$true`.

> Be aware that this might have unexpected implications.

#### Correlation
The correlation is performed on EntityId | MedewekerId. This means that we assume that the employee numbers in NetSuite are equal to your HR/Source systems. So you cannot use automatic numbering. If this is the case in your environment, consider changing to employee numbers. Or perform correlation for example on email address but this is not recommended.

## Setup the connector

> _How to setup the connector in HelloID._ Are special settings required. Like the _primary manager_ settings for a source connector.

The Connector is built out two HelloID Target systems. One *- the Main system-* manages the employees in NetSuite. And the other one is only intended to create user accounts. In the API creating a user account is just a property (GiveAccess) of the Employee object. The separate User connector allows you also to use the business rules to decide which person may be granted with a (login) UserAccount.

The setup of both systems is no different from any other system. But both are required for a full solution, the user connector relies on the Employee Connector. Both connectors using the same config file and configuration.

The **Employee Connector** contains the following scripts:

| Script         | Description                                          | Notes |
| -------------- | ---------------------------------------------------- | ----- |
| Create.ps1     | Creates or Correlates Employee Account (Disabled)    |       |
| Enable.ps1     | Enable the Employee Account *(isInactive = $false )* |       |
| Disable.ps1    | Disable the Employee Account *(isInactive = $true )* |       |
| Update.ps1     | Update Employee accounts                             |       |
| Delete.ps1     | Not implemented                                      |       |
| Permission.ps1 | Not implemented                                      |       |


The **User Connector** only contains a Create and delete script:

| script     | Description                                             | Notes |
| ---------- | ------------------------------------------------------- | ----- |
| Create.ps1 | Correlates the employee account And create user account. <br> Grant a default role which is required to create a Account | :information_source: Important! This connector relies on the account reference from the export data in the employee connector. [Use export data](https://docs.helloid.com/hc/en-us/articles/360014079919#2.2)    |
| Enable.ps1 | Delete User account *(GiveAccess = $false)*              |       |


> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_



## Getting help

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
