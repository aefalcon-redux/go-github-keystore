package timeutils

import (
	"time"
)

func FloatToTime(ts float64) time.Time {
	seconds := int64(ts)
	fraction := ts - float64(seconds)
	nanos := int64(fraction * 1e9)
	return time.Unix(seconds, nanos)
}

func TimeToFloat(t time.Time) float64 {
	unixNano := t.UnixNano()
	floatT := float64(unixNano / int64(1e9))
	floatT += float64(unixNano%1e9) / float64(1e9)
	return floatT
}
