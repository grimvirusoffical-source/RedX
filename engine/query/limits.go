package query

// Limits bounds what one query may cost. Zero fields take the defaults
// (see DefaultLimits); to run without a bound set a very large value
// explicitly.
type Limits struct {
	MaxQueryBytes  int // query text length (default 64 KiB)
	MaxTokens      int // tokens in one query (8192)
	MaxDepth       int // expression nesting (64)
	MaxInList      int // items in one `in` list (1000)
	MaxJoins       int // @> follows in one Get (4)
	MaxTxStmts     int // commands in one Tx (1000)
	MaxPathDepth   int // segments in one field path (16)
	MaxParamBytes  int // size of one string $parameter (1 MiB)
	MaxRows        int // rows one Get may return (10000)
	MaxScan        int // records read from storage by one statement (1,000,000)
	MaxWrites      int // records one Set/Add/Delete (or a whole Tx) may change, cascades included (10000)
	MaxResultBytes int // approximate size of a Get result (16 MiB)
	MaxColumns     int // distinct columns in one result (1024)
}

// DefaultLimits returns the limits used when none are configured.
func DefaultLimits() Limits { return Limits{}.withDefaults() }

func (l Limits) withDefaults() Limits {
	def := func(p *int, v int) {
		if *p <= 0 {
			*p = v
		}
	}
	def(&l.MaxQueryBytes, 64<<10)
	def(&l.MaxTokens, 8192)
	def(&l.MaxDepth, 64)
	def(&l.MaxInList, 1000)
	def(&l.MaxJoins, 4)
	def(&l.MaxTxStmts, 1000)
	def(&l.MaxPathDepth, 16)
	def(&l.MaxParamBytes, 1<<20)
	def(&l.MaxRows, 10000)
	def(&l.MaxScan, 1000000)
	def(&l.MaxWrites, 10000)
	def(&l.MaxResultBytes, 16<<20)
	def(&l.MaxColumns, 1024)
	return l
}
