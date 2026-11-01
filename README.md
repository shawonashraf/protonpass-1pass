# protonpass-1pass

A formatter for csv vault exports from protonpass to be imported into 1password.

**Disclaimer:** I've been recently quite unhappy with the state of ProtonPass in general, e.g. how it fails to autofill on most websites on chromium based browsers unless I refresh, lack of a proper development roadmap for features, and decided to migrate. This project has nothing to do with their recent community debacle.

## pre-requisites

- python 3.14
- protonpass vault exported as a csv file
- (optional, read below) 1password vault exported as a csv file

## usage

```bash
# assuming your 1password vault is new and empty
uv run protonpass-1pass ppass.csv output_dir

# if you have existing items on your 1password vault, then export a csv from there, and then,
uv run protonpass-1pass ppass.csv --exclude-1password 1pass.csv -o output_dir
# this avoids the duplicates in both vaults
```

## limitations

I haven't found a way to directly import notes and payment cards from the exported csv files into 1password. The web importer just assumes that I'm importing login items, for some reason.
