.. Copyright (C) 2019 Wazuh, Inc.

.. _rules_syntax:

Rules Syntax
============

In this section, **xml labels** used to configure ``rules`` are listed.

Available options
-----------------

- `rule`_
- `match`_
- `regex`_
- `decoded_as`_
- `category`_
- `field`_
- `srcip`_
- `dstip`_
- `extra_data`_
- `user`_
- `program_name`_
- `hostname`_
- `time`_
- `weekday`_
- `id`_
- `url`_
- `action`_
- `if_sid`_
- `if_group`_
- `if_level`_
- `if_matched_sid`_
- `if_matched_group`_
- `same_id`_
- `same_source_ip`_
- `same_src_port`_
- `same_dst_port`_
- `same_location`_
- `same_user`_
- `same_field`_
- `not_same_field`_
- `different_url`_
- `different_srcgeoip`_
- `description`_
- `list`_
- `info`_
- `options`_
- `check_diff`_
- `group`_
- `status`_
- `location`_
- `var`_

  - `BAD_WORDS`_

rule
^^^^

``<rule>`` is the label that starts the block that defines a *rule*. In this section the different options to this label are explained.

+---------------+----------------+----------------------------------------------------------------------------------------+
| **level**     | Definition     | Specifies the level of the rule. Alerts and responses use this value.                  |
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | 0 to 16                                                                                |
+---------------+----------------+----------------------------------------------------------------------------------------+
| **id**        | Definition     | Specifies the ID of the rule.                                                          |
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | Any number from 1 to 999999                                                            |
+---------------+----------------+----------------------------------------------------------------------------------------+
| **maxsize**   | Definition     | Specifies the maximum size of the event.                                               |
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | Any number from 1 to 9999                                                              |
+---------------+----------------+----------------------------------------------------------------------------------------+
| **frequency** | Definition     | Number of times the rule must have matched before firing.                              |
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | Any number from 2 to 9999                                                              |
+---------------+----------------+----------------------------------------------------------------------------------------+
| **timeframe** | Definition     | The timeframe in seconds. This option is intended to be used with the frequency option.|
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | Any number from 1 to 99999                                                             |
+---------------+----------------+----------------------------------------------------------------------------------------+
| **ignore**    | Definition     | The time (in seconds) to ignore this rule after firing it (to avoid floods).           |
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | Any number from 1 to 999999                                                            |
+---------------+----------------+----------------------------------------------------------------------------------------+
| **overwrite** | Definition     | Used to supersede an OSSEC rule with local changes.                                    |
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | yes, no                                                                                |
+---------------+----------------+----------------------------------------------------------------------------------------+
| **noalert**   | Definition     | Not trigger any alert if the rule matches.                                             |
+               +----------------+----------------------------------------------------------------------------------------+
|               | Allowed values | Attribute with no value                                                                |
+---------------+----------------+----------------------------------------------------------------------------------------+

Example:

  .. code-block:: xml

    <!--- Rule definition -->
    <rule id="100001" level="3">
      ...
    </rule>


In order to create a custom rule, a rule number and alert level needs to be set. You can use any number
custom number as the rule id. As long as that number doesn't conflict with a current rule. It is recomme
nded to use 100001-999999 to avoid conflict with any current rules.

Example:

  .. code-block:: xml

    <!--- Rule definition -->
    <rule id="100001" maxsize="300" level="3">
      ...
    </rule>

In this example, the rule is assigned with the ID 100001, a maximum size of each event of 300 characters and the rule level in 3.

match
^^^^^
Any string to match against the log event.

+--------------------+-----------------------------------------------------------------+
| **Default Value**  | n/a                                                             |
+--------------------+-----------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_ |
+--------------------+-----------------------------------------------------------------+

Example 1:

  .. code-block:: xml

    <rule id="100001" maxsize="300" level="3">
      <if_sid>100020</if_sid>
      <match>Queue flood!</match>
      <description> Flooded events queue.</description>
    </rule>

If the rule matches the ``id`` 100200 that contains the ``Queue flood!`` phrase in it, rule activates and sends an event.


Example 2:

  .. code-block:: xml

    <rule id="5701" level="8">
      <if_sid>5700</if_sid>
      <match>Bad protocol version identification</match>
      <description>sshd: Possible attack on the ssh server </description>
      <description>(or version gathering).</description>
      <group>pci_dss_11.4,gpg13_4.12,gdpr_IV_35.7.d,</group>
    </rule>

Another example of using match can be seen by examining the existing sshd rules. We are processesing the output of ``sshd``. The sshd program is referenced in rule ``5700`` . We are using ``match`` to specify the output which we would like to use to create the alert. This alert will only be activated when ``sshd`` has an output of ``Bad protocol version identification`` . 


regex
^^^^^

Any regex to match against the log event.

+--------------------+---------------------------------------------------------------+
| **Default Value**  | n/a                                                           |
+--------------------+---------------------------------------------------------------+
| **Allowed values** | Any `regex expression <regex.html#os-regex-or-regex-syntax>`_ |
+--------------------+---------------------------------------------------------------+

Example:

``regex`` is used to find a variety of strings in a rule. For example, if we want to match any valid IP:

  .. code-block:: xml

    <rule id="100001" level="3">
      <if_sid>10050</if_sid>
      <regex>^(\d+.\d+.\d+.\d+)$</regex>
      <description>Matches any valid IP</description>
    </rule>


decoded_as
^^^^^^^^^^

+--------------------+------------------+
| **Default Value**  | n/a              |
+--------------------+------------------+
| **Allowed values** | Any decoder name |
+--------------------+------------------+

Example:

``decoded_as`` is used to reference a decoder. Once the decoder is specificed you can alert for output specific to that decoder.

  .. code-block:: xml

    <rule id="87300" level="0">
      <decoded_as>json</decoded_as>
      <field name="@source">ownCloud</field>
      <description>ownCloud messages grouped.</description>
    </rule>
    
    <rule id="87310" level="0">
      <decoded_as>owncloud</decoded_as>
      <description>ownCloud messages grouped.</description>
    </rule>

    <rule id="100300" level="9">
      <if_sid>87300,87310</if_sid>
      <match>Login failed: 'admin' </match>
      <description>ownCloud authentication failed.</description>
    </rule>

    <rule id="100301" level="9">
      <if_sid>87300,87310</if_sid>
      <match>Login failed: user 'admin' </match>
      <description>ownCloud authentication failed.</description>
    </rule>

In this example, we are using the ``decoded_as`` and applying it to the existing owncloud decoder. Wazuh already has a standard rule for alerting on failed login attempts on ownlcloud, but maybe you want to see failed attempts at the admin account and have them alert on a higher level.

So in our custom rule file, we will create two custom rules  ``100300`` and ``100301`` that reference twoalready built owncloud rules ``87300`` and ``87310``. Rules ``87300`` and ``87310`` use ``decoded_as`` toreference owncloud decoders. Our rule will only alert on failed login of the admin account by only alerting on matching output of  ``Login failed: 'admin'`` or ``Login failed: user 'admin'``. 

category
^^^^^^^^

Selects in which rule decoding category the rule should be included: ids, syslog, firewall, web-log, squid or windows.


+--------------------+--------------+
| **Default Value**  | n/a          |
+--------------------+--------------+
| **Allowed values** | Any category |
+--------------------+--------------+

Example:

  ``category`` is used to specificy a category. You can either reference an existing category or create your own.

  .. code-block:: xml

 <group name="myapplication,">
  <rule id="100200" level="0">
    <category>myapplication</category>
    <description>Rules for my application</description>
 </rule>

We created a ``group`` and ``category`` for ``myapplication``. You can now use your ``category`` as a filter to create or edit kibana dashboards for alerts about ``myapplication``. 

field
^^^^^

Any ``OS_Regex`` to be compared to a field extracted by the decoder.

+----------+-----------------------------------------------------------+
| **name** | Specifies the name of the field extracted by the decoder. |
+----------+-----------------------------------------------------------+

Example:

  ``field`` can be used to specify a field value. We can specify to only alert on Error Severity levels for a specific exe file. 

  .. code-block:: xml

  <rule id="100321" level="9">
    <if_sid>60003</if_sid>
    <field name="win.system.severityValue">^ERROR$</field>
    <description> My application error event</description>
    <options>no_full_log</options>
    <match>myapp.exe</match>
  </rule>


srcip
^^^^^

Any IP address or CIDR block to be compared to an IP decoded as srcip. Use "!" to negate it.

+--------------------+-----------+
| **Default Value**  | n/a       |
+--------------------+-----------+
| **Allowed values** | Any srcip |
+--------------------+-----------+

dstip
^^^^^

Any IP address or CIDR block to be compared to an IP decoded as dstip. Use "!" to negate it.

+--------------------+-----------+
| **Default Value**  | n/a       |
+--------------------+-----------+
| **Allowed values** | Any dstip |
+--------------------+-----------+

extra_data
^^^^^^^^^^

Any string that is decoded into the extra_data field.

+--------------------+-------------+
| **Default Value**  | n/a         |
+--------------------+-------------+
| **Allowed values** | Any string. |
+--------------------+-------------+

user
^^^^

Any username (decoded as the username).

+--------------------+------------------------------------------------------------------+
| **Default Value**  | n/a                                                              |
+--------------------+------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_  |
+--------------------+------------------------------------------------------------------+

program_name
^^^^^^^^^^^^

Program name is decoded from syslog process name.

+--------------------+------------------------------------------------------------------+
| **Default Value**  | n/a                                                              |
+--------------------+------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_  |
+--------------------+------------------------------------------------------------------+

hostname
^^^^^^^^

Any hostname (decoded as the syslog hostname) or log file.

+--------------------+------------------------------------------------------------------+
| **Default Value**  | n/a                                                              |
+--------------------+------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_  |
+--------------------+------------------------------------------------------------------+

time
^^^^

Time that the event was generated.

+--------------------+----------------------------------------------------------------------+
| **Default Value**  | n/a                                                                  |
+--------------------+----------------------------------------------------------------------+
| **Allowed values** | Any time range (hh:mm-hh:mm, hh:mm am-hh:mm pm, hh-hh, hh am-hh pm)  |
+--------------------+----------------------------------------------------------------------+

weekday
^^^^^^^

Week day that the event was generated.

+--------------------+-------------------------------------+
| **Default Value**  | n/a                                 |
+--------------------+-------------------------------------+
| **Allowed values** | monday - sunday, weekdays, weekends |
+--------------------+-------------------------------------+

id
^^

Any ID (decoded as the ID).

+--------------------+------------------------------------------------------------------+
| **Default Value**  | n/a                                                              |
+--------------------+------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_  |
+--------------------+------------------------------------------------------------------+

url
^^^

Any URL (decoded as the URL).

+--------------------+------------------------------------------------------------------+
| **Default Value**  | n/a                                                              |
+--------------------+------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_  |
+--------------------+------------------------------------------------------------------+

location
^^^^^^^^

.. versionadded:: 3.5.0

The event extended location of the incoming event.

+--------------------+------------------------------------------------------------------+
| **Default Value**  | n/a                                                              |
+--------------------+------------------------------------------------------------------+
| **Allowed values** | Any `sregex expression <regex.html#os-match-or-sregex-syntax>`_  |
+--------------------+------------------------------------------------------------------+

The location identifies the origin of the input. If the event comes from an agent, its name and registered IP (as it was added) is appended to the location.

Example of a location for a log pulled from "/var/log/syslog" in an agent with name "dbserver" and registered with IP "any":

::

    (dbserver) any->/var/log/syslog

The following components use a static location:

+----------------------+------------------------+
| **Component**        | **Location**           |
+----------------------+------------------------+
| Windows Eventchannel | EventChannel           |
+----------------------+------------------------+
| Windows Eventlog     | WinEvtLog              |
+----------------------+------------------------+
| FIM (Syscheck)       | syscheck               |
+----------------------+------------------------+
| Rootcheck            | rootcheck              |
+----------------------+------------------------+
| Syscollector         | syscollector           |
+----------------------+------------------------+
| Vuln Detector        | vulnerability-detector |
+----------------------+------------------------+
| Azure Logs           | azure-logs             |
+----------------------+------------------------+
| AWS S3 integration   | aws-s3                 |
+----------------------+------------------------+
| Docker integration   | Wazuh-Docker           |
+----------------------+------------------------+
| Osquery integration  | osquery                |
+----------------------+------------------------+
| OpenSCAP integration | open-scap              |
+----------------------+------------------------+
| CIS-CAT integration  | wodle_cis-cat          |
+----------------------+------------------------+

action
^^^^^^

Any action (decoded as the ACTION).

+--------------------+----------------------+
| **Default Value**  | n/a                  |
+--------------------+----------------------+
| **Allowed values** | Any String.          |
+--------------------+----------------------+

if_sid
^^^^^^

Matches if the ID has matched.

+--------------------+-------------+
| **Default Value**  | n/a         |
+--------------------+-------------+
| **Allowed values** | Any rule id |
+--------------------+-------------+

if_group
^^^^^^^^

Matches if the group has matched before.

+--------------------+-----------+
| **Default Value**  | n/a       |
+--------------------+-----------+
| **Allowed values** | Any Group |
+--------------------+-----------+

if_level
^^^^^^^^

Matches if the level has matched before.

+--------------------+------------------------+
| **Default Value**  | n/a                    |
+--------------------+------------------------+
| **Allowed values** | Any level from 1 to 16 |
+--------------------+------------------------+

if_matched_sid
^^^^^^^^^^^^^^

Matches if an alert of the defined ID has been triggered in a set number of seconds.

This option is used in conjunction with frequency and timeframe.

+--------------------+-------------+
| **Default Value**  | n/a         |
+--------------------+-------------+
| **Allowed values** | Any rule id |
+--------------------+-------------+

.. note::
  Rules at level 0 are discarded immediately and will not be used with the if_matched_rules. The level must be at least 1, but the <no_log> option can be added to the rule to make sure it does not get logged.

if_matched_group
^^^^^^^^^^^^^^^^

Matches if an alert of the defined group has been triggered in a set number of seconds.

This option is used in conjunction with frequency and timeframe.

+--------------------+-----------+
| **Default Value**  | n/a       |
+--------------------+-----------+
| **Allowed values** | Any Group |
+--------------------+-----------+


same_id
^^^^^^^

Specifies that the decoded id must be the same.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <same_id />        |
+--------------------+--------------------+

same_source_ip
^^^^^^^^^^^^^^

Specifies that the decoded source ip must be the same.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <same_source_ip /> |
+--------------------+--------------------+

same_src_port
^^^^^^^^^^^^^

Specifies that the decoded source port must be the same.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <same_src_port />  |
+--------------------+--------------------+

same_dst_port
^^^^^^^^^^^^^

Specifies that the decoded destination port must be the same.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <same_dst_port />  |
+--------------------+--------------------+

same_location
^^^^^^^^^^^^^

Specifies that the location must be the same.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <same_location />  |
+--------------------+--------------------+

same_user
^^^^^^^^^

Specifies that the decoded user must be the same.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <same_user />      |
+--------------------+--------------------+

same_field
^^^^^^^^^^

Specifies that the decoded field must be the same as the previous one.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <same_field />     |
+--------------------+--------------------+

As an example of this option, check this rule:

.. code-block:: xml

  <rule id="100001" level="3">
    <if_sid>221</if_sid>
    <field name="netinfo.iface.name">ens33</field>
    <description>Testing interface alert</description>
  </rule>

  <rule id="100002" level="7" frequency="3" timeframe="300">
    <if_matched_sid>100001</if_matched_sid>
    <same_field>netinfo.iface.mac</same_field>
    <description>Testing options for correlating repeated fields</description>
  </rule>

.. note::

  Rule 100002 will trigger when the last three events had the same `netinfo.iface.mac` address.

not_same_field
^^^^^^^^^^^^^^

Specifies that the decoded field must be different than the previous one.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <not_same_field /> |
+--------------------+--------------------+


As an example of this option, check this rule:

.. code-block:: xml

  <rule id="100001" level="3">
    <if_sid>221</if_sid>
    <field name="netinfo.iface.name">ens33</field>
    <description>Testing interface alert</description>
  </rule>

  <rule id="100002" level="7" frequency="3" timeframe="300">
    <if_matched_sid>100001</if_matched_sid>
    <not_same_field>netinfo.iface.mac</not_same_field>
    <description>Testing options for correlating repeated fields</description>
  </rule>

.. note::

  Rule 100002 will trigger when the last three events do not have the same `netinfo.iface.mac` address.

different_url
^^^^^^^^^^^^^

Specifies that the decoded url must be different.
This option is used in conjunction with frequency and timeframe.

+--------------------+--------------------+
| **Example of use** | <different_url />  |
+--------------------+--------------------+

different_srcgeoip
^^^^^^^^^^^^^^^^^^

Specifies that the source geoip location must be different.
This option is used in conjunction with frequency and timeframe.

+--------------------+------------------------+
| **Example of use** | <different_srcgeoip /> |
+--------------------+------------------------+

Example:

  As an example to this last options, check this rule:

    .. code-block:: xml

      <rule id=100005 level="0">
        <match> Could not open /home </match>
        <same_user />
        <different_srcgeoip />
        <same_dst_port />
      </rule>

  That rule filters when the same ``user`` tries to open file ``/home`` but returns an error, on a different ``ip`` and using same ``port``.

description
^^^^^^^^^^^

Used to add a description to a rule so it makes more clear and readable its funcionality.
This option apports more readable information for the users, so is usually added to the rules.

+--------------------+------------+
| **Default Value**  | n/a        |
+--------------------+------------+
| **Allowed values** | Any string |
+--------------------+------------+

Examples:

  .. code-block:: xml

    <rule id="100009" level="1">
      ...
      <regex>^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$</regex>
      <description> Rule to match IPs </description>
    </rule>

    <rule id="100015" level="2">
      ...
      <description> A timeout occured. </description>
    </rule>

    <rule id="100035" level="4">
      ...
      <description> File missing. Root acces unrestricted. </description>
    </rule>

Since Wazuh version 3.3 it is possible to include any decoded field (static or dynamic) to the description message. You can use the following syntax: ``$(field_name)`` to add a field to the description.

Example:

  .. code-block:: xml

    <rule id="100005" level="8">
      <match>illegal user|invalid user</match>
      <description>sshd: Attempt to login using a non-existent user from IP $(attempt_ip)</description>
      <options>no_log</options>
    </rule>


list
^^^^

Perform a CDB lookup using an ossec list.  This is a fast on disk database which will always find keys within two seeks of the file.

+--------------------+-------------------------------------------------------------------------------------------------------------------+
| **Default Value**  | n/a                                                                                                               |
+--------------------+-------------------------------------------------------------------------------------------------------------------+
| **Allowed values** | Path to the CDB file to be used for lookup from the OSSEC directory.Must also be included in the ossec.conf file. |
+--------------------+-------------------------------------------------------------------------------------------------------------------+

+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
| Attribute       | Description                                                                                                                       |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
| **field**       | key in the CDB: srcip, srcport, dstip, dstport, extra_data, user, url, id, hostname, program_name, status, action, dynamic field. |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
| **lookup**      | match_key               | key to search within the cdb and will match if they key is present. Default.                            |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
|                 | not_match_key           | key to search and will match if it is not present in the database.                                      |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
|                 | match_key_value         | searched for in the cdb. It will be compared with regex from attribute check_value.                     |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
|                 | address_match_key       | IP and the key to search within the cdb and will match if they key is present.                          |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
|                 | not_address_match_key   | IP the key to search and will match if it IS NOT present in the database                                |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
|                 | address_match_key_value | IP to search in the cdb. It will be compared with regex from attribute check_value.                     |
+-----------------+-------------------------+---------------------------------------------------------------------------------------------------------+
| **check_value** | regex for matching on the value pulled out of the cdb when using types: address_match_key_value, match_key_value                  |
+-----------------+-----------------------------------------------------------------------------------------------------------------------------------+

info
^^^^

Extra information may be added through the following attributes:

+--------------------+------------+
| **Default Value**  | n/a        |
+--------------------+------------+
| **Allowed values** | Any string |
+--------------------+------------+

+-----------+----------------+-----------------------------------------------------------------------------------------------------------+
| Attribute | Allowed values | Description                                                                                               |
+-----------+----------------+-----------------------------------------------------------------------------------------------------------+
| type      | **text**       | This is the default when no type is selected. Additional,information about the alert/event.               |
+           +----------------+-----------------------------------------------------------------------------------------------------------+
|           | **link**       | Link to more information about the alert/event.                                                           |
+           +----------------+-----------------------------------------------------------------------------------------------------------+
|           | **cve**        | The CVE Number related to this alert/event.                                                               |
+           +----------------+-----------------------------------------------------------------------------------------------------------+
|           | **ovsdb**      | The osvdb id related to this alert/event.                                                                 |
+-----------+----------------+-----------------------------------------------------------------------------------------------------------+

.. _rules_options:

options
^^^^^^^

Additional rule options.

+--------------------+-----------------------------------------------------+
| Attribute          | Description                                         |
+====================+=====================================================+
| **alert_by_email** | Always alert by email.                              |
+--------------------+-----------------------------------------------------+
| **no_email_alert** | Never alert by email.                               |
+--------------------+-----------------------------------------------------+
| **no_log**         | Do not log this alert.                              |
+--------------------+-----------------------------------------------------+
| **no_full_log**    | Do not include the ``full_log`` field in the alert. |
+--------------------+-----------------------------------------------------+
| **no_counter**     | Omit field ``rule.firedtimes`` in the JSON alert.   |
+--------------------+-----------------------------------------------------+

Example:

  .. code-block:: xml

    <rule id="9800" level="8">
      <match>illegal user|invalid user</match>
      <description>sshd: Attempt to login using a non-existent user</description>
      <options>no_log</options>
    </rule>

.. note::
  Use one ``<options>`` tag for each option you want to add.

.. _rules_check_diff:

check_diff
^^^^^^^^^^

Used to determine when the output of a command changes.

+--------------------+--------------------+
| **Example of use** | <check_diff />     |
+--------------------+--------------------+

group
^^^^^

Add additional groups to the alert. Groups are optional tags added to alerts.

They can be used by other rules by using if_group or if_matched_group, or by alert parsing tools to categorize alerts.

Groups are variables that define a behaviour. When an alert includes that group label, this behaviour will occur.

Example:

  .. code-block:: xml

    <rule id="3801" level="4">
      <description>Group for rules related with spam.</description>
      <group>spam,</group>
    </rule>

Now, every rule with the line ``<group>spam,</group>`` will be included in that group.

It's a very useful label to keep the rules ordered.

+--------------------+------------+
| **Default Value**  | n/a        |
+--------------------+------------+
| **Allowed values** | Any String |
+--------------------+------------+

status
^^^^^^

Declares the actual status of a rule.

+--------------------+----------------------------------------------+
| **Default Value**  | n/a                                          |
+--------------------+----------------------------------------------+
| **Allowed values** | started, aborted, succedeed, failed, lost... |
+--------------------+----------------------------------------------+

var
^^^

Defines a variable that may be used in any place of the same file.

+----------------+------------------------+
| Attribute      | Value                  |
+================+========================+
| **name**       | Name for the variable. |
+----------------+------------------------+

Example:

  .. code-block:: xml

     <var name="joe_folder">/home/joe/</var>

      <group name="local,">

        <rule id="100001" level="5">
          <if_sid>550</if_sid>
          <field name="file">^$joe_folder</field>
          <description>A Joe's file was modified.</description>
          <group>ossec,pci_dss_10.6.1,gpg13_10.1,gdpr_IV_35.7.d,</group>
        </rule>

    </group>

BAD_WORDS
^^^^^^^^^

<var name="BAD_WORDS">error|warning|failure</var>

``BAD_WORDS`` is a very used use case of ``<var>`` option.

Is used to include many words in the same variable. Later, this variable can be matched into the decoders to check if any of those words are in a caught event.

Example:

  .. code-block:: xml

    <var name="BAD_WORDS">error|warning|failure</var>

    <group name="syslog,errors,">
      <rule id="XXXX" level="2">
        <match>$BAD_WORDS</match>
        <description>Error found.</description>
      </rule>
    </group>
