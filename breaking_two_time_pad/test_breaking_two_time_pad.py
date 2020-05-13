import breaking_two_time_pad as bttp

def test_convert_cribbed_to_regex():
    assert bttp.convert_cribbed_to_regex("robab ") == ['.*robab$']
    assert bttp.convert_cribbed_to_regex(" robab") == ['^robab.*']
    assert bttp.convert_cribbed_to_regex("rob ab") == ['.*rob$', '^ab.*']
    assert bttp.convert_cribbed_to_regex("a b c") == ['.*a$', '^b$', '^c.*']
    assert bttp.convert_cribbed_to_regex(" a b c") == ['^a$', '^b$', '^c.*']
    assert bttp.convert_cribbed_to_regex("a b c ") == ['.*a$', '^b$', '^c$']
    assert bttp.convert_cribbed_to_regex(" a b c ") == ['^a$', '^b$', '^c$']
    assert bttp.convert_cribbed_to_regex(" a b c d e f g h ") == ['^a$', '^b$', '^c$', '^d$', '^e$', '^f$', '^g$', '^h$']
