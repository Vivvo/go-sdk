package models;


//Service Card Callback - Format we expect for call backs to the CitizenOne Platform
type ServiceCardCallbackDto struct {
	Files   []ServiceCardFileDto  `json:"files"`
	Labels  []ServiceCardLabelDto `json:"labels"`
	Actions []ServiceCardTaskDto  `json:"actions"`
}