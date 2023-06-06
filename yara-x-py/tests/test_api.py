import pytest
import yara_x

def test_syntax_error():
  compiler = yara_x.Compiler()
  with pytest.raises(SyntaxError):
    compiler.add_source('bad rule')

def test_bad_variable_type():
  compiler = yara_x.Compiler()
  with pytest.raises(TypeError):
    compiler.define_global()

def test_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_int', 1);
  compiler.add_source('rule test {condition: some_int == 1}')
  rules = compiler.build()
  scanner = yara_x.Scanner(rules)
  matches = scanner.scan(b'')
  assert len(matches) == 1
  scanner.set_global('some_int', 2)
  matches = scanner.scan(b'')
  assert len(matches) == 0

def test_compile_and_scan():
  rules = yara_x.compile('rule foo {strings: $a = "foo" condition: $a}')
  matches = rules.scan(b"foobar")
  assert len(matches) == 1

def test_compiler_and_scanner():
  compiler = yara_x.Compiler()
  compiler.add_source('rule foo {strings: $a = "foo" condition: $a}')
  scanner = yara_x.Scanner(compiler.build())
  matches = scanner.scan(b"foobar")
  assert len(matches) == 1