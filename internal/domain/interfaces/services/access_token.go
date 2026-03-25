package services

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
)

type AccessToken interface {
	Generate(command commands.Generate) (*results.Generate, error)
	Parse(command commands.Parse) (*results.Parse, error)
}
