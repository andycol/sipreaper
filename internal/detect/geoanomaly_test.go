package detect

import (
	"net"
	"testing"
	"time"

	"github.com/andycol/sipreaper/internal/models"
)

type mockGeoResolver struct {
	countries map[string]string
}

func (m *mockGeoResolver) Country(ip net.IP) (string, error) {
	if c, ok := m.countries[ip.String()]; ok {
		return c, nil
	}
	return "XX", nil
}

func TestGeoAnomalyBlocksNonAllowed(t *testing.T) {
	resolver := &mockGeoResolver{
		countries: map[string]string{
			"1.2.3.4": "RU",
		},
	}
	d := NewGeoAnomaly([]string{"GB", "US"}, resolver)

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: net.ParseIP("1.2.3.4"), Method: "REGISTER",
	}
	threat := d.Detect(evt)
	if threat == nil {
		t.Fatal("expected threat for non-allowed country")
	}
	if threat.Detector != "geo_anomaly" {
		t.Errorf("detector = %q, want geo_anomaly", threat.Detector)
	}
}

func TestGeoAnomalyAllowsPermittedCountry(t *testing.T) {
	resolver := &mockGeoResolver{
		countries: map[string]string{
			"5.6.7.8": "GB",
		},
	}
	d := NewGeoAnomaly([]string{"GB", "US"}, resolver)

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: net.ParseIP("5.6.7.8"), Method: "REGISTER",
	}
	threat := d.Detect(evt)
	if threat != nil {
		t.Error("allowed country should not trigger threat")
	}
}

func TestGeoAnomalyDisabledWhenNoCountries(t *testing.T) {
	d := NewGeoAnomaly(nil, nil)

	evt := models.SIPEvent{
		Timestamp: time.Now(), SourceIP: net.ParseIP("1.2.3.4"), Method: "REGISTER",
	}
	threat := d.Detect(evt)
	if threat != nil {
		t.Error("should not trigger when no allowed countries configured")
	}
}
