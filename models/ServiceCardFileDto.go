package models;


//Service Card File structure
type ServiceCardFileDto struct {
	Title       string `json:"title"`
	Action      string `json:"action"`
	Description string `json:"description"`
	FileType    string `json:"fileType"`
	FileSize    string `json:"fileSize"`
	Date        string `json:"date"`
}