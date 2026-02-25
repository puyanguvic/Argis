Feature name Design

Author(s): <Your Name/n000000000>

Status: <Intent to implement/Discarded/Obsolete>

> **IMPORTANT** |<br>
> **IMPORTANT** | Every section here is **MANDATORY**. If you believe a section does not<br>
> **IMPORTANT** | apply, you can add a line explaining why it does not apply.<br>
> **IMPORTANT** | **ALL** these sections have repeatedly shown to be necessary<br>
> **IMPORTANT** | to complete the design. If you skip them initially you will<br>
> **IMPORTANT** | only **delay** consensus and approval.<br>
> **IMPORTANT** |<br>
> **IMPORTANT** | Do yourself a favour and do it right the first time.<br>
> **IMPORTANT** |<br>

[[_TOC_]]

Introduction
============

Introduce your feature here in a way that any newly hired, experienced developer could come onto the team and understand
what the feature is and why we are doing it. This section shouldn't dive deeply into the technologies involved.

Background
==========

In this section you should lay out any necessary background for the feature. This should include things like what sort of
support or infrastructure is already existing that this design is building upon. Any libraries, frameworks, or external
technologies should be explained at a high level here. Any
[standards (RFC7540 section 6.0)](https://www.rfc-editor.org/rfc/rfc7540.html#section-6.9)
documents or manuals should be linked here and linked from the reference section. Linking from both places make references
easy to jump to without reading the document fully.

Scope
=====

Clearly lay out the scope of this design, both in respect to component or architecural boundaries and functionality.
Frequently designs interact with other components which are important but tangental to the design itself. For example,
a parser design will work within a larger stream processing framework, but the parser design won't deal with any details of
that framework which are not directly relevant to the parser. Similarly, rarely are features ever fully completed. Instead
work happens in waves as functionality becomes prioritized versus other features.

This section lays out what is and is not part of this design. If documents exist for the adjacent components or additonal
phases of development, it is helpful to link them here.

Architecture overview
=====================

Explain the high level architecture of all the components within this design and how they interact. Use diagrams and
explanatory text to do so. The goal is to give readers a high level understanding of how everything described below fits
together. In-depth explanations should be left to the respective section on the design of the component.

It is important that you include a block diagram showing the relationship between all the components discussed below.

> A hint about diagrams and figures. Huawei is a multilingual company so diagrams in a single language tend not to work well
> for everybody. If the team works in multiple languages, try to ensure all text within the diagram is multilingual. If this
> is not possible for space reasons, then ensure every block of text has a visible number. In the explanation of the diagram
> each number should have a textual description, repeating the text in the diagram and expanding upon it if appropriate.
>
> There are good tools to translate text between languages, but none of them work on images. Creating diagrams in this way
> allows effective use of these translation tools.
>
> There are three recommended tools to create diagrams. In order of preference these are the built in Gitlab integrations with
> [PlantUML](https://rnd-gitlab-ca-y.huawei.com/help/administration/integration/plantuml.md) and
> [Mermaid](https://rnd-gitlab-ca-y.huawei.com/help/user/markdown.md#mermaid), and raw SVG diagrams using
> [diagrams.net](https://www.diagrams.net/) (prefer the downloaded desktop version). The advantage of these formats is that
> they are easy to modify and can have per-line review comments, more so in the PlantUML and Mermaid cases.
>
> SVG images should be uploaded (perhaps using the WebIDE), then included in the Markdown document as an image
> (![Caption](image_filename.svg)).

> **IMPORTANT** |<br>
> **IMPORTANT** | A diagram showing the relationship between **ALL** the<br>
> **IMPORTANT** | components discussed in this document is **MANDATORY**.<br>
> **IMPORTANT** | Skipping it will only add to confusion and **delay**<br>
> **IMPORTANT** | consensus and approval.<br>
> **IMPORTANT** |<br>
> **IMPORTANT** | Do yourself a favour and do it right the first time.<br>
> **IMPORTANT** |<br>

Component A
===========

Now that you've laid out the high level architecture it is time to explain how each component works. Use as much detail as you
feel is appropriate, but avoid dropping to the level of code except for the most complex of issues. Use numerous diagrams which
are accompanied by prose explanation of the diagram.

Component B
===========

Interaction between Component A and Component B
===============================================

Sections like this one will not exist in every design document. However, if the design requires complex interactions between
multiple components which are not suitable to be placed under any single component design above, then you can create a section
specifically to discuss them.

Configuration
=============

Describe the high level configuration processing plan. Often this briefly summarizes which component parses/uses which high-level
XML elements.

Notation
--------

For conciseness, closing tags are abbreviated as </>.

xml-element-1
-------------

| Element&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Possible values                           | Description        |
| ----------------------------------- | --------------------------- | ------------------------ |
| <xml-element-1> | | Top-level element which encapsulates the config |
|     <option1>true</> | true, false | Enable/disable option1. See XXXXXXX |
|     <container> | | XXXXXXX |
|       <expire>10 min</> | Time period in human units | Validity period |
|       <method>SMS</> | [SMS \| token \| email] | XXXXXXXXX |
|     </container> | |
| </xml-element-1> | |

Describe the XML structure and the meaning of any non-obvious fields. This must contain a concrete example of a typical
configuration. If the configuration is complex, then individual sub-elements should be explicitly explained. Try to
ensure that every element is understandable to somebody who understands intermediate networking and has fully read the
background section.

Complex fields should contain a link to the relevant section which explains the values and behaviours.

Try to keep the XML line from wrapping when Gitlab is opened at its widest. Increase to decrease the number of &nbsp;
characters as necessary.

xml-element-2
-------------

Testing
=======

Discuss your automated testing strategy here. This should include the broad design of new test harnesses or extensions of
existing test harnesses if necessary. If neither of those are necessary, then say so. You don't need to list every test
you intend to write, but should cover the broad categories.

Task breakdown
==============

Here you should do a rough breakdown and estimation of the various stages of implementing this feature or task. Do keep
an eye towards keeping each task to no more than one week of estimated time, and keep each task small enough that it will
be easy to merge. Also, try and keep mergability in mind; we want each task to be merged to master/develop and therefore
accessibly to other developers in a timely manner. We do not want to need to wait until the last task is complete before
merging. This requires that each task keeps the codebase in a working state, either through code toggles or some other
means.

The table below is a summary of the broken down tasks which should be briefly described below it. The tracker column
should be left empty until this desgin has been made a part of a sprint. Time estimates should be between 0.5 days and 1
week. Longer tasks should be broken up if at all possible. If that isn't possible, then possibly the feature should be
broken up into several phases.

| Task              | Time Estimate | Tracker |
| ----------------- | ------------- | ------- |
| Task 1            | 1 week        |   #1    |
| Task 2            | 0.5 days      |         |
| Task 3            | 2 days        |         |

## Task 1

One or two lines about what Task 1 involves.

## Task 2

Task 2 involves...

## Task 3

Task 3 involves...

References
==========

Insert links to any relevant references here.

RFC7540 section 6.9: https://www.rfc-editor.org/rfc/rfc7540.html#section-6.9
