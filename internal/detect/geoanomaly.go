package detect

import (
	"fmt"
	"net"
	"time"

	"github.com/andycol/sipreaper/internal/models"
	geoip2 "github.com/oschwald/geoip2-golang"
)

// GeoResolver looks up the country for an IP address.
type GeoResolver interface {
	Country(ip net.IP) (string, error)
}

type GeoAnomaly struct {
	allowed  map[string]bool
	resolver GeoResolver
}

func NewGeoAnomaly(allowedCountries []string, resolver GeoResolver) *GeoAnomaly {
	allowed := make(map[string]bool, len(allowedCountries))
	for _, c := range allowedCountries {
		allowed[c] = true
	}
	return &GeoAnomaly{
		allowed:  allowed,
		resolver: resolver,
	}
}

func (d *GeoAnomaly) Name() string { return "geo_anomaly" }

func (d *GeoAnomaly) Detect(event models.SIPEvent) *models.Threat {
	if len(d.allowed) == 0 || d.resolver == nil {
		return nil
	}

	country, err := d.resolver.Country(event.SourceIP)
	if err != nil {
		return nil
	}

	if d.allowed[country] {
		return nil
	}

	return &models.Threat{
		Timestamp:   time.Now(),
		SourceIP:    event.SourceIP,
		Detector:    "geo_anomaly",
		Severity:    "medium",
		Description: fmt.Sprintf("request from non-allowed country: %s", country),
		EventCount:  1,
		Window:      0,
	}
}

// MaxMindResolver uses a GeoLite2 database for lookups.
type MaxMindResolver struct {
	db *geoip2.Reader
}

func NewMaxMindResolver(dbPath string) (*MaxMindResolver, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening geoip db: %w", err)
	}
	return &MaxMindResolver{db: db}, nil
}

func (r *MaxMindResolver) Country(ip net.IP) (string, error) {
	code, _, err := r.CountryInfo(ip)
	return code, err
}

func (r *MaxMindResolver) CountryInfo(ip net.IP) (code, name string, err error) {
	record, err := r.db.Country(ip)
	if err != nil {
		return "", "", err
	}
	name = record.Country.Names["en"]
	return record.Country.IsoCode, name, nil
}

func (r *MaxMindResolver) Close() error {
	return r.db.Close()
}
