package models


//Service Card Task Structure - The main structure of a task
type ServiceCardTaskDto struct {
	Label       string                 `json:"label"`
	Description string                 `json:"description"`
	Style       ServiceCardTaskStyle          `json:"style"`
	Type        ServiceCardTaskType           `json:"type"`
	Params      map[string]interface{} `json:"params"`
	SubTasks    []ServiceCardSubTaskDto       `json:"subtasks"`
}
