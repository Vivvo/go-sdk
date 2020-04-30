package models

//Service Card Task Type - The type of task
//CONTAINER - The main structure of the task.  The big text section on the task
//ACTION - The action of the task -> A link where it points to
//FORM - A link to the form used in this sub-task
type ServiceCardTaskType string

const (
	CONTAINER ServiceCardTaskType = "CONTAINER"
	ACTION    ServiceCardTaskType = "ACTION"
	FORM      ServiceCardTaskType = "FORM"
)

//Service Card Task Style - Style is in form of bootstrap styles
//Example: https://getbootstrap.com/docs/4.4/components/alerts/
type ServiceCardTaskStyle string

const (
	PRIMARY ServiceCardTaskStyle = "PRIMARY"
	SUCCESS ServiceCardTaskStyle = "SUCCESS"
	DANGER  ServiceCardTaskStyle = "DANGER"
	WARNING ServiceCardTaskStyle = "WARNING"
	INFO    ServiceCardTaskStyle = "INFO"
)

//Service Card Sub Task Structure
type ServiceCardSubTaskDto struct {
	Label       string                 `json:"label"`
	Description string                 `json:"description"`
	Style       ServiceCardTaskStyle   `json:"style"`
	Action      string                 `json:"action"`
	Type        ServiceCardTaskType    `json:"type"`
	Params      map[string]interface{} `json:"params"`
}
