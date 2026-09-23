import sys
from unittest.mock import patch

from phishscope.cli import create_parser, main


def test_parser_creation():
    """Test that the parser is created with expected subcommands."""
    parser = create_parser()
    assert parser is not None
    assert parser.prog == "phishscope"


def test_cli_no_args(capsys):
    """Test CLI behavior when no arguments are provided."""
    with patch.object(sys, "argv", ["phishscope"]):
        exit_code = main()
        assert exit_code == 2

        captured = capsys.readouterr()
        assert "usage:" in captured.err


def test_cli_analyze_command(capsys):
    """Test the basic execution of the analyze command structure."""
    with patch.object(sys, "argv", ["phishscope", "analyze", "samples/plain_text.eml"]):
        exit_code = main()
        assert exit_code == 0

        captured = capsys.readouterr()
        # Check for expected output
        assert "Analyzing:" in captured.out
        assert "samples/plain_text.eml" in captured.out
        assert "Parsing Successful!" in captured.out


def test_cli_detect_command(capsys):
    """Test the basic execution of the detect command structure."""
    test_args = ["phishscope", "detect", "--rules", "rules/", "--logs", "logs/"]
    with patch.object(sys, "argv", test_args):
        exit_code = main()
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "Sigma detection not yet implemented" in captured.out
