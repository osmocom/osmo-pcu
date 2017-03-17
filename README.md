osmo-pcu - Osmocom Packet Control Unit
======================================

This repository contains a C/C++-language implementation of a GPRS
Packet Control Unit, as specified by ETSI/3GPP.  It is part of the
[Osmocom](https://osmocom.org/) Open Source Mobile Communications
project.

The Packet Control Unit is terminating the Layer 2 (RLC/MAC) of the GPRS
radio interface and adapting it to the Gb Interface (BSSGP+NS Protocol)
towards the SGSN.

The PCU interfaces with the physical layer of the radio interface.
OsmoPCU is typically used co-located with the BTS, specifically
[OsmoBTS](https://osmocom.org/projects/osmobts/wiki).
For legacy BTSs that run proprietary sotware without an interface to
OsmoPCU, you may also co-locate it with the BSC, specifically
[OsmoBSC](https://osmocom.org/projects/openbsc/wiki/Osmo-bsc)

Homepage
--------

The official homepage of the project is
https://osmocom.org/projects/osmopcu/wiki/OsmoPCU

GIT Repository
--------------

You can clone from the official osmo-pcu.git repository using

	git clone git://git.osmocom.org/osmo-pcu.git

There is a cgit interface at http://git.osmocom.org/osmo-pcu/

Documentation
-------------

We provide a
[user manual](http://ftp.osmocom.org/docs/latest/osmopcu-usermanual.pdf)
as well as a
[vty reference manual](http://ftp.osmocom.org/docs/latest/osmopcu-vty-reference.pdf)

Please note that a lot of the PCU configuration actually happens inside
the BSC, which passes this configuration via A-bis OML to the BTS, which
then in turn passes it via the PCU socket into OsmoPCU.

Mailing List
------------

Discussions related to osmo-pcu are happening on the
osmocom-net-gprs@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/osmocom-net-gprs for
subscription options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards

We us a gerrit based patch submission/review process for managing
contributions.  Please see
https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit for
more details

The current patch queue for osmo-pcu can be seen at
https://gerrit.osmocom.org/#/q/project:osmo-pcu+status:open


Current limitations
-------------------

 * No PFC support
 * No fixed allocation support
 * No extended dynamic allocation support
 * No unacknowledged mode operation
 * Only single slot assignment on uplink direction
 * No half-duplex class support (only semi-duplex)
 * No TA loop
 * No power loop
