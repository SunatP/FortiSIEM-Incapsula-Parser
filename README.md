# FortiSIEM Incapsula WAF Parser Custom

## Why did we create a custom Incapsula WAF for FortiSIEM?

Because the latest version of FortiSIEM doesn't support this parser or API yet. Furthermore, __Common Event Format__(CEF) logs that have come to the FortiSIEM will be parsed to the **generic CEF** instead.

## The structure of the parser

```xml
<patternDefinitions>
    <!-- Defines the parsing patterns that are iterated over by the parsing instructions -->
</patternDefinitions>
<eventFormatRecognizer>
	<!-- Patterns that determine whether an event will be parsed by this parser -->
</eventFormatRecognizer>
<parsingInstructions>
    <!-- Instructions on how to parse events that match the format recognizer patterns -->
</parsingInstructions>
```

## What is Regex and, why should we use this one?

**Regex** or Regular Expression is a sequence of characters that specifies a search pattern.
We use Regex to match the character or combination in strings

## CEF log of Incapsula WAF Incident header fields

```md
CEF:0|Incapsula|SIEMintegration|1|1|Bot Access Control|4| Body msg
```

| Field Name      | Description | Value/use     |
| :---        |    :----   |          :--- |
|Version| 	An integer that identifies the version of the CEF format.| 	0|
|Device Vendor| 	The vendor that is generating the logs.| 	Incapsula|
|Device Product| 	The product that is generating the logs.| 	SIEMintegration|
|Device Version |	The version of the product that is generating the logs.| 	1|
|Signature ID| 	The violation type, such as Illegal Resource Access.| 	1|
|Name| 	Description of the incident, such as "Illegal Resource Access attack from a single IP using Chrome Browser".| 	Bot Access Control|
|Severity| 	The risk level of the incident: CRITICAL, MAJOR, MINOR, CUSTOM 	|4|
|Raw Body Msg| The raw message that we need Regex for parsing data and mapping to each event|?|

### Log Example

```md
CEF:0|Imperva Inc|Attack Analytics|0|Illegal Resource Access|Illegal Resource Access attack from a single IP using Chrome Browser |MAJOR| msg=Illegal Resource Access attack from a single IP using Chrome Browser  start=1553494500466 end=1553494505753 src=1.2.3.4 dhost=weblogstest.test.info request=/cmd.exe requestClientApplication=Chrome cs1=9 cs1Label=ImpervaAANumberOfEvents cs2=100 cs2Label=ImpervaAAPercentBlocked cs3=Germany cs3Label=ImpervaAACountry cs4=CloudWAF cs4Label=ImpervaAAPlatform cs5=1.2.3.4 cs5Label=ImpervaAADominantIps cs6=3418038110000000127-10656037459001,3418038110000000127-10664627393593,3418038110000000127-3668125668403 cs6Label=ImpervaAASampleEvents cs7=Illegal Resource Access cs7Label=ImpervaAAAttackType cs8=1080105,10801030,1080104 cs8Label=ImpervaAADominantSiteIds cs9=CVE-2013-0632,CVE-2008-3257,CVE-2017-5638,CVE-2016-3087 cs9Label=ImpervaAACves
```

## Parser for parsing this data

```xml
<patternDefinitions>
	<pattern name="patStrSepPipe">
		<![CDATA[[^|]*]]>
	</pattern>
	<pattern name="patInt">
		<![CDATA[\d]]>
	</pattern>
	<pattern name="gPatMesgBody">
		<![CDATA[.*]]>
	</pattern>
</patternDefinitions>

<eventFormatRecognizer>
	<![CDATA[CEF:\d+\|Incapsula\|SIEMintegration\|]]>
</eventFormatRecognizer>

<parsingInstructions>
<collectFieldsByRegex src="$_rawmsg">
		<regex>
			<![CDATA[CEF:\d\|<reptVendor:gPatMesgBodyMin>\|<reptModel:gPatStr>\|<_devVersion:gPatStr>\|<_signatureID:patInt>\|<eventName:gPatMesgBodyMin>\|<eventSeverity:gPatInt>\|<_body:gPatMesgBody>]]>
		</regex>
	</collectFieldsByRegex>
</parsingInstructions>
```