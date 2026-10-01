package llm

import "strings"

// price is USD per million tokens, Claude API list prices (September
// 2026). A 5-minute cache write costs 1.25x input.
type price struct {
	input, output, cacheRead float64
}

var prices = map[string]price{
	"claude-fable-5-1":  {10, 50, 0.25},
	"claude-opus-5-5":   {4, 20, 0.20},
	"claude-opus-5":     {5, 25, 0.50},
	"claude-opus-4-8":   {5, 25, 0.50},
	"claude-opus-4-7":   {5, 25, 0.50},
	"claude-opus-4-6":   {5, 25, 0.50},
	"claude-sonnet-5-5": {2, 10, 0.20},
	"claude-sonnet-5":   {2, 10, 0.20},
	"claude-sonnet-4-6": {3, 15, 0.30},
	"claude-haiku-4-5":  {1, 5, 0.10},
}

// Cost estimates what a call cost in USD. ok is false for a model
// without a known price.
func Cost(u Usage) (usd float64, ok bool) {
	p, ok := priceOf(u.Model)
	if !ok {
		return 0, false
	}
	const m = 1e6
	usd = float64(u.Input)*p.input/m +
		float64(u.Output)*p.output/m +
		float64(u.CacheRead)*p.cacheRead/m +
		float64(u.CacheWrite)*p.input*1.25/m
	return usd, true
}

// priceOf also recognizes dated snapshots and provider prefixes
// (claude-haiku-4-5-20251001, anthropic.claude-opus-5-5): the longest
// known ID in the name wins, so claude-opus-5-5 isn't priced as
// claude-opus-5.
func priceOf(model string) (price, bool) {
	if p, ok := prices[model]; ok {
		return p, true
	}
	best := ""
	for id := range prices {
		if strings.Contains(model, id) && len(id) > len(best) {
			best = id
		}
	}
	p, ok := prices[best]
	return p, ok
}
