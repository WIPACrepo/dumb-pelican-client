# dumb-pelican-client

Like the [Pelican client](https://docs.pelicanplatform.org/getting-data-with-pelican/client) for putting and getting files, but simpler and more correct.

Currently only works with HTCondor credentials, by searching the _CONDOR_CREDS dir.

## Example usage

Get a file:

```
$ dumb_pelican_client object get <url> <filename>
```


Put a file:

```
$ dumb_pelican_client object put <filename> <url>
```
