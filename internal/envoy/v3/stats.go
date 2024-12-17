// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	"slices"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_filter_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_filter_network_http_connection_manager_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_transport_socket_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/wrapperspb"

	contour_v1alpha1 "github.com/projectcontour/contour/apis/projectcontour/v1alpha1"
	"github.com/projectcontour/contour/internal/protobuf"
)

// StatsListenerConfig holds properties used to construct different [*envoy_config_listener_v3.Listener]s
// that can serve:
//   - prometheus metrics on /stats (either over HTTP or HTTPS)
//   - readiness/liveness probe on /ready (always over HTTP)
//   - cherry-picked admin routes (always over HTTP)
type StatsListenerConfig struct {
	address        string
	port           int
	classes        []listenerClass
	metricsTLS     bool
	metricsCA      string
	ignoreOMLimits bool
}

type (
	listenerClass string
	// ListenerOption configures [StatsListenerConfig] properties
	ListenerOption func(l *StatsListenerConfig)
)

const (
	metricsServerCertSDSName = "metrics-tls-certificate"
	metricsCaBundleSDSName   = "metrics-ca-certificate"

	metricsClass listenerClass = "stats" // `stats` retains the old listener naming conventions
	healthClass  listenerClass = "health"
	adminClass   listenerClass = "envoy-admin"
)

// NewStatsListenerConfig constructs a [*StatsListenerConfig] for a given address and port. When multiple
// routing [ListenerOption]s are be provided the resulting listener paths are joined
func NewStatsListenerConfig(address string, port int, opts ...ListenerOption) *StatsListenerConfig {
	l := &StatsListenerConfig{
		address: address,
		port:    port,
	}
	for _, o := range opts {
		o(l)
	}

	return l
}

// MetricsRouting returns a [ListenerOption] that configures the following listener routes:
//   - /stats
//   - /stats/prometheus
func MetricsRouting() ListenerOption {
	return func(l *StatsListenerConfig) {
		l.classes = append(l.classes, metricsClass)
	}
}

// HealthRouting returns a [ListenerOption] that configures the following listener routes:
//   - /ready
func HealthRouting() ListenerOption {
	return func(l *StatsListenerConfig) {
		l.classes = append(l.classes, healthClass)
	}
}

// AdminRouting returns a [ListenerOption] that configures the following listener routes:
//   - /certs
//   - /clusters
//   - /listeners
//   - /config_dump
//   - /memory
//   - /ready
//   - /runtime
//   - /server_info
//   - /stats
//   - /stats/prometheus
//   - /stats/recentlookups"
func AdminRouting() ListenerOption {
	return func(l *StatsListenerConfig) {
		l.classes = append(l.classes, adminClass)
	}
}

// MetricsTLS returns a [ListenerOption] that configures the DownstreamTlsContext when protecting metrics routes.
// This only applies when used with [MetricsRouting].
func MetricsTLS(caFile string) ListenerOption {
	return func(l *StatsListenerConfig) {
		l.metricsTLS = true
		l.metricsCA = caFile
	}
}

// IgnoreOverloadManagerLimits returns a [ListenerOption] that configures the listener to ignore downstream connection
// limits configured by the overload manager.
func IgnoreOverloadManagerLimits() ListenerOption {
	return func(l *StatsListenerConfig) {
		l.ignoreOMLimits = true
	}
}

// ToEnvoy generates an envoy listener configuration. The resulting listener name is based on the different routing
// [ListenerOption]s used to construct the [StatsListenerConfig]. Listener names are suffixed with [-om-enforced] unless
// [IgnoreOverloadManagerLimits] is used.
func (stats *StatsListenerConfig) ToEnvoy() *envoy_config_listener_v3.Listener {
	if len(stats.classes) == 0 {
		return nil
	}

	var tlsTransportSocket *envoy_config_core_v3.TransportSocket
	if slices.Contains(stats.classes, metricsClass) && stats.metricsTLS {
		tlsTransportSocket = DownstreamTLSTransportSocket(
			downstreamTLSContext(stats.metricsCA != ""))
	}

	var classesAsString []string
	var prefixes []string
	for _, cls := range stats.classes {
		classesAsString = append(classesAsString, string(cls))
		switch cls {
		case metricsClass:
			prefixes = append(prefixes, "/stats", "/stats/prometheus")
		case healthClass:
			prefixes = append(prefixes, "/ready")
		case adminClass:
			prefixes = append(
				prefixes,
				"/certs",
				"/clusters",
				"/listeners",
				"/config_dump",
				"/memory",
				"/ready",
				"/runtime",
				"/server_info",
				"/stats",
				"/stats/prometheus",
				"/stats/recentlookups",
			)
		}
	}

	// Strip duplicate routes prefixes
	slices.Sort(prefixes)
	prefixes = slices.Compact(prefixes)

	listenerName := strings.Join(classesAsString, "-")
	if !stats.ignoreOMLimits {
		listenerName += "-om-enforced"
	}

	return &envoy_config_listener_v3.Listener{
		Name:                  listenerName,
		Address:               SocketAddress(stats.address, stats.port),
		SocketOptions:         NewSocketOptions().TCPKeepalive().Build(),
		FilterChains:          filterChain("stats", tlsTransportSocket, routeForAdminInterface(prefixes...)),
		IgnoreGlobalConnLimit: stats.ignoreOMLimits,
	}
}

// filterChain returns a filter chain used by static listeners.
func filterChain(statsPrefix string, transportSocket *envoy_config_core_v3.TransportSocket, routes *envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig) []*envoy_config_listener_v3.FilterChain {
	return []*envoy_config_listener_v3.FilterChain{{
		Filters: []*envoy_config_listener_v3.Filter{{
			Name: wellknown.HTTPConnectionManager,
			ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
				TypedConfig: protobuf.MustMarshalAny(&envoy_filter_network_http_connection_manager_v3.HttpConnectionManager{
					StatPrefix:     statsPrefix,
					RouteSpecifier: routes,
					HttpFilters: []*envoy_filter_network_http_connection_manager_v3.HttpFilter{{
						Name: wellknown.Router,
						ConfigType: &envoy_filter_network_http_connection_manager_v3.HttpFilter_TypedConfig{
							TypedConfig: protobuf.MustMarshalAny(&envoy_filter_http_router_v3.Router{}),
						},
					}},
					NormalizePath: wrapperspb.Bool(true),
				}),
			},
		}},
		TransportSocket: transportSocket,
	}}
}

// routeForAdminInterface creates static RouteConfig that forwards requested paths to Envoy admin interface.
func routeForAdminInterface(paths ...string) *envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig {
	config := &envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
		RouteConfig: &envoy_config_route_v3.RouteConfiguration{
			VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
				Name:    "backend",
				Domains: []string{"*"},
			}},
		},
	}

	for _, p := range paths {
		config.RouteConfig.VirtualHosts[0].Routes = append(config.RouteConfig.VirtualHosts[0].Routes,
			&envoy_config_route_v3.Route{
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
						Path: p,
					},
					Headers: []*envoy_config_route_v3.HeaderMatcher{
						{
							Name: ":method",
							HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
								StringMatch: &envoy_matcher_v3.StringMatcher{
									IgnoreCase: true,
									MatchPattern: &envoy_matcher_v3.StringMatcher_Exact{
										Exact: "GET",
									},
								},
							},
						},
					},
				},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: "envoy-admin",
						},
					},
				},
			},
		)
	}
	return config
}

// downstreamTLSContext creates TLS context when HTTPS is used to protect Envoy stats endpoint.
// Certificates and key are hardcoded to the SDS secrets which are returned by StatsSecrets.
func downstreamTLSContext(clientValidation bool) *envoy_transport_socket_tls_v3.DownstreamTlsContext {
	context := &envoy_transport_socket_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_transport_socket_tls_v3.CommonTlsContext{
			TlsParams: &envoy_transport_socket_tls_v3.TlsParameters{
				TlsMinimumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
				TlsMaximumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
			},
			TlsCertificateSdsSecretConfigs: []*envoy_transport_socket_tls_v3.SdsSecretConfig{{
				Name:      metricsServerCertSDSName,
				SdsConfig: ConfigSource("contour"),
			}},
		},
	}

	if clientValidation {
		context.CommonTlsContext.ValidationContextType = &envoy_transport_socket_tls_v3.CommonTlsContext_ValidationContextSdsSecretConfig{
			ValidationContextSdsSecretConfig: &envoy_transport_socket_tls_v3.SdsSecretConfig{
				Name:      metricsCaBundleSDSName,
				SdsConfig: ConfigSource("contour"),
			},
		}
		context.RequireClientCertificate = wrapperspb.Bool(true)
	}

	return context
}

// StatsSecrets returns SDS secrets that refer to local file paths in Envoy container.
func StatsSecrets(metricsTLS *contour_v1alpha1.MetricsTLS) []*envoy_transport_socket_tls_v3.Secret {
	secrets := []*envoy_transport_socket_tls_v3.Secret{}

	if metricsTLS != nil {
		if metricsTLS.CertFile != "" && metricsTLS.KeyFile != "" {
			secrets = append(secrets, &envoy_transport_socket_tls_v3.Secret{
				Name: metricsServerCertSDSName,
				Type: &envoy_transport_socket_tls_v3.Secret_TlsCertificate{
					TlsCertificate: &envoy_transport_socket_tls_v3.TlsCertificate{
						CertificateChain: &envoy_config_core_v3.DataSource{
							Specifier: &envoy_config_core_v3.DataSource_Filename{
								Filename: metricsTLS.CertFile,
							},
						},
						PrivateKey: &envoy_config_core_v3.DataSource{
							Specifier: &envoy_config_core_v3.DataSource_Filename{
								Filename: metricsTLS.KeyFile,
							},
						},
					},
				},
			})
		}
		if metricsTLS.CAFile != "" {
			secrets = append(secrets, &envoy_transport_socket_tls_v3.Secret{
				Name: metricsCaBundleSDSName,
				Type: &envoy_transport_socket_tls_v3.Secret_ValidationContext{
					ValidationContext: &envoy_transport_socket_tls_v3.CertificateValidationContext{
						TrustedCa: &envoy_config_core_v3.DataSource{
							Specifier: &envoy_config_core_v3.DataSource_Filename{
								Filename: metricsTLS.CAFile,
							},
						},
					},
				},
			})
		}
	}

	return secrets
}
