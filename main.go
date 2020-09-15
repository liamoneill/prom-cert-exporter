package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr = flag.String("listen-address", ":8080", "The address to listen on for HTTP requests.")

	certificateExpiryDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prom_cert_exporter_expiry_duration_seconds",
			Help: "Duration in seconds until certificate expires",
		},
		[]string{"server", "certificate"},
	)
)

func init() {
	prometheus.MustRegister(certificateExpiryDuration)
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())
}

func sniffCertificates(address string) ([]*x509.Certificate, error) {
	// TODO timeout
	conn, err := tls.Dial("tcp", address, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		return nil, err
	}

	return conn.ConnectionState().PeerCertificates, nil
}

func main() {
	flag.Parse()

	go func() {
		for {
			for _, server := range []string{"example.com:443", "example.net:443"} {
				certs, err := sniffCertificates(server)
				if err != nil {
					log.Printf("Encounted error sniffing certificates for server [%s]: %s\n", server, err)
					continue
				}

				for _, cert := range certs {
					expiryDuration := cert.NotAfter.Sub(time.Now())
					certificateExpiryDuration.
						WithLabelValues(server, cert.Subject.String()).
						Set(float64(expiryDuration) / float64(time.Second))
				}
			}

			time.Sleep(1 * time.Minute)
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(*addr, nil))
}
