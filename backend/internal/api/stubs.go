package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Stub handlers for endpoints that will be implemented later
// These return 501 Not Implemented for now

// Containers
func (h *Handler) listContainers(c *gin.Context)    { c.JSON(http.StatusOK, []interface{}{}) }
func (h *Handler) getContainer(c *gin.Context)      { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) startContainer(c *gin.Context)    { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) stopContainer(c *gin.Context)     { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) restartContainer(c *gin.Context)  { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) getContainerLogs(c *gin.Context)  { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) listStacks(c *gin.Context)        { c.JSON(http.StatusOK, []interface{}{}) }

// Logs
func (h *Handler) getNginxLogs(c *gin.Context)   { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) getUnifiedLogs(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }

// Databases
func (h *Handler) listDatabases(c *gin.Context)      { c.JSON(http.StatusOK, []interface{}{}) }
func (h *Handler) addDatabase(c *gin.Context)        { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) removeDatabase(c *gin.Context)     { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) getDatabaseMetrics(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }

// Alerts
func (h *Handler) listAlertChannels(c *gin.Context)  { c.JSON(http.StatusOK, []interface{}{}) }
func (h *Handler) createAlertChannel(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) updateAlertChannel(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) deleteAlertChannel(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) testAlertChannel(c *gin.Context)   { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }

func (h *Handler) listAlertRules(c *gin.Context)   { c.JSON(http.StatusOK, []interface{}{}) }
func (h *Handler) createAlertRule(c *gin.Context)  { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) updateAlertRule(c *gin.Context)  { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) deleteAlertRule(c *gin.Context)  { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) getAlertHistory(c *gin.Context)  { c.JSON(http.StatusOK, []interface{}{}) }

// Audit
func (h *Handler) getAuditLogs(c *gin.Context) { c.JSON(http.StatusOK, []interface{}{}) }

// Users
func (h *Handler) listUsers(c *gin.Context)  { c.JSON(http.StatusOK, []interface{}{}) }
func (h *Handler) createUser(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) updateUser(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
func (h *Handler) deleteUser(c *gin.Context) { c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"}) }
