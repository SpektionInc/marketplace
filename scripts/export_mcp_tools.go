// Run from the spektionapi module. No service startup or credentials required.
package main

import (
	"encoding/json"
	"os"
	"sort"

	"restAPI/src/aitools"
	"restAPI/src/aitools/mcpadapter"
)

func main() {
	mcpTools, chatTools := []any{}, []any{}
	specs := append([]aitools.Spec(nil), aitools.Registry()...)
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	for _, s := range specs {
		params, lanes := []any{}, []string{}
		if s.Lanes.Includes(aitools.LaneChat) {
			lanes = append(lanes, "chat")
		}
		if s.Lanes.Includes(aitools.LaneMCP) {
			lanes = append(lanes, "mcp")
		}
		for _, p := range s.Params {
			param := map[string]any{"name": p.Name, "type": p.Type, "required": p.Required}
			if len(p.Enum) > 0 {
				param["enum"] = p.Enum
			}
			if p.Type == aitools.ParamArray {
				param["item_type"] = p.ItemType
			}
			params = append(params, param)
		}
		t := map[string]any{"name": s.Name, "description": s.Description, "read_only": s.ReadOnly, "lanes": lanes, "params": params}
		if s.Lanes.Includes(aitools.LaneMCP) {
			mcpTools = append(mcpTools, t)
		} else {
			chatTools = append(chatTools, t)
		}
	}
	wire := mcpadapter.Tools(aitools.LaneMCP)
	sort.Slice(wire, func(i, j int) bool { return wire[i].Name < wire[j].Name })
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"mcp": map[string]any{"tools": mcpTools}, "chat_only_tools": chatTools, "tools_list": wire}); err != nil {
		panic(err)
	}
}
