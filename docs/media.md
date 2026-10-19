# Media

Package `engine/media`. Media libraries are served by the host with HTTP `Range` support; see the [API reference](api.md#boxql-media-access-policy-scripts-and-encryption).

## Media libraries (`.red-xai-media`)

An item is two things in a `pack`:

* a **data file** `data/<name>/<token>` (content-addressed 1 MiB chunks, so identical
  chunks are shared). `<token>` is 32 random hex chars, new for every version.
* a **sealed manifest** `meta/<name>.red-xai-media`:

```
{Media[]= [
    {Version[]} = 1, {Name[]} = "cat.png", {Type[]} = "image", {MIME[]} = "image/png",
    {Size[]} = 1234, {SHA256[]} = "<hex>", {Path[]} = "data/cat.png/<token>",
    {Width[]} = 64, {Height[]} = 48
];
{Seal[]} = "<sha256 of every byte above>";
```

`DurationMs` / `DurationEstimated` appear for audio and video when they can be read. Width,
height and duration are omitted when unknown. Manifests are ≤ 64 KiB and are verified
against their seal on every read.

### API (`engine/media`)

`New(files, chunks, Config{Root, MaxSize, MaxRangeRead}) (*Store, error)`, where `files`
is any `media.Files` (`*pack.Pack` fits) and `chunks` any `media.Chunks`
(`GetChunk(id)`; every `pack.ChunkStore` fits).

| call | what it does |
|------|--------------|
| `Put(name, r, PutOptions{Declared})` | sniff, check declared type, write data, then manifest. Replaces an existing item. |
| `Stat`, `List` | manifests. `List` reports items whose manifest is damaged as entries with an error rather than failing. |
| `Open(name) (*Reader, error)` | `io.Reader`, `io.Seeker`, `io.ReaderAt`, `Size()`, `Meta()`, `Close()`. Works with `http.ServeContent`. |
| `ReadRange(name, off, length)` | bytes `[off, off+length)`, clipped at EOF; at most `MaxRangeRead` per call. |
| `Verify(name)` | reads everything, checks every chunk, the file hash and the size. |
| `Fsck(deep)`, `Sweep()` | find (and with `Sweep`, delete) orphan data files / orphan manifests. Never deletes an item whose manifest exists, even a damaged one. |
| `Delete(name)` | manifest first (the item disappears), then the data. Works on a damaged item. |
| `ParseRange(header, size)`, `ContentRange(off, length, size)` | single-range HTTP `Range` parsing (`bytes=a-b`, `a-`, `-n`). Malformed → `ErrBadRange` (HTTP: ignore the header), several ranges → `ErrMultiRange`, start past EOF → `ErrUnsatisfiable`. |

Defaults: `DefaultMaxSize` 4 GiB per item, `DefaultMaxRangeRead` 64 MiB per `ReadRange`.
Names: one valid pack file name, no `/`, length-bounded (`ErrInvalidName`).

### Content sniffing (no transcoding, ever)

`Sniff(head)` needs the first 4096 bytes (`SniffLen`) and returns type, canonical MIME and extension.

| format | magic bytes | type / MIME |
|--------|-------------|-------------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | image/png |
| JPEG | `FF D8 FF` | image/jpeg |
| GIF | `GIF87a` / `GIF89a` | image/gif |
| WebP | `RIFF....WEBP` | image/webp |
| WAV | `RIFF....WAVE` | audio/wav |
| MP3 | `ID3` tag, or an MPEG audio frame sync with valid header fields | audio/mpeg |
| OGG | `OggS`, then the first packet decides: Vorbis/Opus/FLAC/Speex → audio/ogg, Theora → video/ogg, otherwise audio/ogg (also accepts a `video/ogg` declaration) | audio/ogg, video/ogg |
| MP4 | `ftyp` box at offset 4; audio-only brands (`M4A `) → audio/mp4, otherwise video/mp4 | video/mp4, audio/mp4 |

Anything else (including formats that merely look similar, e.g. SVG, AVI, MKV) is `ErrUnsupported`.
The declared type can be a MIME type (parameters and common aliases such as `image/jpg`,
`audio/mp3`, `audio/x-wav` are normalised) or just `image` / `audio` / `video`. If it
disagrees with the bytes: `ErrTypeMismatch`, and nothing is stored. An empty declaration accepts the sniffed type.

### Probing

`Probe` reads only headers, with bounded reads: PNG/GIF/JPEG/WebP dimensions, WAV duration
(exact, from the `fmt` and `data` chunks), MP3 duration (estimated from the first frame's
bitrate, so `DurationEstimated = true`), OGG duration (from the last page's granule position), MP4 duration (from `mvhd`) and
dimensions (from `tkhd`). A malformed header just means "unknown", never an error.

### Reads and verification

`pack` has no ranged read, so the Reader uses `pack.Info` (chunk ids, chunk size, size)
and fetches only the chunks a range touches, each verified (SHA-256 of the chunk against its id) before use. A small chunk cache
is kept per Reader. `Open` first checks that the data file still matches the manifest (size, chunk count, hash).
A ranged read **cannot** check the whole-file hash (it never sees the whole file); `Verify` does.

### Crash behaviour

Order on `Put`: data under a **fresh** path, then manifest (the commit point), then best-effort delete of the old data.
A crash before the manifest leaves the old version fully intact plus an orphan data file that `Fsck` reports and `Sweep` deletes.
A crash after the manifest leaves the new version plus an orphan old data file. Tested with `pack.MemBackend`'s crash hook at every step.

Limits: roughly 50k items per `Root` (a pack folder holds one sealed manifest, see [Indexes and packs](indexes-and-packs.md)).

## Limitations

* No transcoding, thumbnails or streaming-format (HLS/DASH) support.
* MP3 duration is an estimate.
* About 50,000 items per library folder.
* A media library matched by an `Encrypt` rule is refused, because range reads over ciphertext are not implemented.
* Library contents are local to a node and are not replicated.
