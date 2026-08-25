package server

import (
	"log/slog"

	"cypture/internal/models"
)

func (s *Server) audit(actorID, action, targetType, targetID, detail, ip string) {
	entry := models.AuditLog{
		ActorID:    actorID,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Detail:     detail,
		IP:         ip,
	}
	if err := s.DB.Create(&entry).Error; err != nil {
		slog.Warn("audit write failed", "action", action, "err", err)
	}
}
