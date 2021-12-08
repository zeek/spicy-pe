# @TEST-EXEC: zeek -r ${TRACES}/ftp-pe.pcap %INPUT
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff pe.log
#
# @TEST-DOC: Test PE analyzer with an executable transferred over FTP, with the calculation of the section entropy enabled


@load analyzer

redef PE::pe_log_section_entropy=T;
