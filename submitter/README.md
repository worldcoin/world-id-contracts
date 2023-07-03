# Identity Submitter
A utility to submit identities to the signup sequencer.

## Usage
Given a file with identities, which should look something like this:
```
0x0007A64593D0B80725672FA34CB5A4A7122ACC7D9E471FC01A8B6080A99B7FF7
0x000798358E06F05504A6BDD3B66AF1789FD02E5C7E49998326DFF9392ECE31EA
0x0007A6220846A3EB229C21DD1FECEFC546DFA62EAB1AA1114D4768691FCDCDE7
0x00079B11F603289886A5F8CD24650543D2AD9DD5083661CD37A7335B57903675
0x00079935C8E85CEE55A08FFB16A5C7EC0C0045B65B03E73C7F779A87E646BD52
0x0007A5EB7468A09AD0BF21037377A3228F10209ED7495A8F19C9B74E97E60AFD
0x000790D286016D0248623CD7FCFB58E55E1D6E1D4635A102A30C6136D1287666
0x0007B497EE10B21518818101021934D6C08F3113A8B5134BCDC59AD2D38438A8
0x0007B9AF076043AEAD48804C40D13BBC0283FC6D8949463086B4BB4D70ABA543
0x0007E097D809FF88F603DAAEEE0AC244761B1D24AA80D1CC8CB552002E07EB1F
```

Simply run
```bash
> cargo run --release -- submit -i identities/identities_to_submit -u identities/unprocessed -s <SEQUENCER_URL_WITH_BASIC_AUTH>
```

to submit identities to the given sequencer. Note that the url should contain basic auth credentials.

The submitter will continuously save all the identities which are yet unprocessed to the file under the `-u/--unprocessed-file` argument. So if the process fails at any point, you can resume from where it left off by running:

```bash
> cargo run --release -- submit -i identities/unprocessed -u identities/unprocessed -s <SEQUENCER_URL_WITH_BASIC_AUTH>
```

Use `--help` for usage of commands other than `submit`
