import argparse

class LoadFromFile (argparse.Action):
  # a custom argparse.Action that opens the file, 
  # parses the file contents and then adds the arguments.
    def __call__ (self, parser, namespace, values, option_string = None):
      with values as f:
        parser.parse_args(f.read().split(), namespace)
