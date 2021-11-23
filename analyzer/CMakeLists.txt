spicy_add_analyzer(
    NAME PE
    PACKAGE_NAME PE
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
