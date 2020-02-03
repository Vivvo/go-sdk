package models

type PublishWrapperDto struct {
	EventType string      `json:"eventType"`
	Data      interface{} `json:"data"`
}
