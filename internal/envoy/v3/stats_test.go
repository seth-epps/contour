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
	"testing"

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

func TestStatsTLSSecrets(t *testing.T) {
	type testcase struct {
		metricsTLS contour_v1alpha1.MetricsTLS
		want       []*envoy_transport_socket_tls_v3.Secret
	}
	run := func(t *testing.T, name string, tc testcase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()
			protobuf.ExpectEqual(t, tc.want, StatsSecrets(&tc.metricsTLS))
		})
	}

	run(t, "only-server-credentials", testcase{
		metricsTLS: contour_v1alpha1.MetricsTLS{
			CertFile: "certfile",
			KeyFile:  "keyfile",
		},
		want: []*envoy_transport_socket_tls_v3.Secret{{
			Name: "metrics-tls-certificate",
			Type: &envoy_transport_socket_tls_v3.Secret_TlsCertificate{
				TlsCertificate: &envoy_transport_socket_tls_v3.TlsCertificate{
					CertificateChain: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_Filename{
							Filename: "certfile",
						},
					},
					PrivateKey: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_Filename{
							Filename: "keyfile",
						},
					},
				},
			},
		}},
	})

	run(t, "with-client-authentication", testcase{
		metricsTLS: contour_v1alpha1.MetricsTLS{
			CertFile: "certfile",
			KeyFile:  "keyfile",
			CAFile:   "cabundle",
		},
		want: []*envoy_transport_socket_tls_v3.Secret{{
			Name: "metrics-tls-certificate",
			Type: &envoy_transport_socket_tls_v3.Secret_TlsCertificate{
				TlsCertificate: &envoy_transport_socket_tls_v3.TlsCertificate{
					CertificateChain: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_Filename{
							Filename: "certfile",
						},
					},
					PrivateKey: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_Filename{
							Filename: "keyfile",
						},
					},
				},
			},
		}, {
			Name: "metrics-ca-certificate",
			Type: &envoy_transport_socket_tls_v3.Secret_ValidationContext{
				ValidationContext: &envoy_transport_socket_tls_v3.CertificateValidationContext{
					TrustedCa: &envoy_config_core_v3.DataSource{
						Specifier: &envoy_config_core_v3.DataSource_Filename{
							Filename: "cabundle",
						},
					},
				},
			},
		}},
	})
}

func TestNewStatsListenerConfig(t *testing.T) {
	route := func(path string) *envoy_config_route_v3.Route {
		return &envoy_config_route_v3.Route{
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: path,
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
		}
	}

	type testcase struct {
		address string
		port    int
		opts    []ListenerOption
		want    *envoy_config_listener_v3.Listener
	}

	run := func(t *testing.T, name string, tc testcase) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()
			got := NewStatsListenerConfig(tc.address, tc.port, tc.opts...)
			protobuf.ExpectEqual(t, tc.want, got.ToEnvoy())
		})
	}

	run(t, "no-routes", testcase{
		address: "",
		port:    1,
		want:    nil,
	})

	run(t, "metrics-routes", testcase{
		address: "127.0.0.127",
		port:    8123,
		opts:    []ListenerOption{MetricsRouting()},
		want: &envoy_config_listener_v3.Listener{
			Name:    "stats-om-enforced",
			Address: SocketAddress("127.0.0.127", 8123),
			FilterChains: FilterChains(
				&envoy_config_listener_v3.Filter{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: protobuf.MustMarshalAny(&envoy_filter_network_http_connection_manager_v3.HttpConnectionManager{
							StatPrefix: "stats",
							RouteSpecifier: &envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
								RouteConfig: &envoy_config_route_v3.RouteConfiguration{
									VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
										Name:    "backend",
										Domains: []string{"*"},
										Routes:  []*envoy_config_route_v3.Route{route("/stats"), route("/stats/prometheus")},
									}},
								},
							},
							HttpFilters: []*envoy_filter_network_http_connection_manager_v3.HttpFilter{{
								Name: wellknown.Router,
								ConfigType: &envoy_filter_network_http_connection_manager_v3.HttpFilter_TypedConfig{
									TypedConfig: protobuf.MustMarshalAny(&envoy_filter_http_router_v3.Router{}),
								},
							}},
							NormalizePath: wrapperspb.Bool(true),
						}),
					},
				},
			),
			SocketOptions: NewSocketOptions().TCPKeepalive().Build(),
		},
	})

	run(t, "metrics-health-routes", testcase{
		address: "127.0.0.127",
		port:    8123,
		opts:    []ListenerOption{MetricsRouting(), HealthRouting()},
		want: &envoy_config_listener_v3.Listener{
			Name:    "stats-health-om-enforced",
			Address: SocketAddress("127.0.0.127", 8123),
			FilterChains: FilterChains(
				&envoy_config_listener_v3.Filter{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: protobuf.MustMarshalAny(&envoy_filter_network_http_connection_manager_v3.HttpConnectionManager{
							StatPrefix: "stats",
							RouteSpecifier: &envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
								RouteConfig: &envoy_config_route_v3.RouteConfiguration{
									VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
										Name:    "backend",
										Domains: []string{"*"},
										Routes:  []*envoy_config_route_v3.Route{route("/ready"), route("/stats"), route("/stats/prometheus")},
									}},
								},
							},
							HttpFilters: []*envoy_filter_network_http_connection_manager_v3.HttpFilter{{
								Name: wellknown.Router,
								ConfigType: &envoy_filter_network_http_connection_manager_v3.HttpFilter_TypedConfig{
									TypedConfig: protobuf.MustMarshalAny(&envoy_filter_http_router_v3.Router{}),
								},
							}},
							NormalizePath: wrapperspb.Bool(true),
						}),
					},
				},
			),
			SocketOptions: NewSocketOptions().TCPKeepalive().Build(),
		},
	})

	run(t, "metrics-health-admin-routes", testcase{
		address: "127.0.0.127",
		port:    8123,
		opts:    []ListenerOption{MetricsRouting(), HealthRouting(), AdminRouting()},
		want: &envoy_config_listener_v3.Listener{
			Name:    "stats-health-envoy-admin-om-enforced",
			Address: SocketAddress("127.0.0.127", 8123),
			FilterChains: FilterChains(
				&envoy_config_listener_v3.Filter{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: protobuf.MustMarshalAny(&envoy_filter_network_http_connection_manager_v3.HttpConnectionManager{
							StatPrefix: "stats",
							RouteSpecifier: &envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
								RouteConfig: &envoy_config_route_v3.RouteConfiguration{
									VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
										Name:    "backend",
										Domains: []string{"*"},
										Routes: []*envoy_config_route_v3.Route{
											route("/certs"),
											route("/clusters"),
											route("/config_dump"),
											route("/listeners"),
											route("/memory"),
											route("/ready"),
											route("/runtime"),
											route("/server_info"),
											route("/stats"),
											route("/stats/prometheus"),
											route("/stats/recentlookups"),
										},
									}},
								},
							},
							HttpFilters: []*envoy_filter_network_http_connection_manager_v3.HttpFilter{{
								Name: wellknown.Router,
								ConfigType: &envoy_filter_network_http_connection_manager_v3.HttpFilter_TypedConfig{
									TypedConfig: protobuf.MustMarshalAny(&envoy_filter_http_router_v3.Router{}),
								},
							}},
							NormalizePath: wrapperspb.Bool(true),
						}),
					},
				},
			),
			SocketOptions: NewSocketOptions().TCPKeepalive().Build(),
		},
	})

	run(t, "metric-routes-tls-with-no-ca", testcase{
		address: "127.0.0.127",
		port:    8123,
		opts:    []ListenerOption{MetricsRouting(), MetricsTLS("")},
		want: &envoy_config_listener_v3.Listener{
			Name:    "stats-om-enforced",
			Address: SocketAddress("127.0.0.127", 8123),
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: protobuf.MustMarshalAny(&envoy_filter_network_http_connection_manager_v3.HttpConnectionManager{
							StatPrefix: "stats",
							RouteSpecifier: &envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
								RouteConfig: &envoy_config_route_v3.RouteConfiguration{
									VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
										Name:    "backend",
										Domains: []string{"*"},
										Routes:  []*envoy_config_route_v3.Route{route("/stats"), route("/stats/prometheus")},
									}},
								},
							},
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
				TransportSocket: DownstreamTLSTransportSocket(
					&envoy_transport_socket_tls_v3.DownstreamTlsContext{
						CommonTlsContext: &envoy_transport_socket_tls_v3.CommonTlsContext{
							TlsParams: &envoy_transport_socket_tls_v3.TlsParameters{
								TlsMinimumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
								TlsMaximumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
							},
							TlsCertificateSdsSecretConfigs: []*envoy_transport_socket_tls_v3.SdsSecretConfig{{
								Name:      "metrics-tls-certificate",
								SdsConfig: ConfigSource("contour"),
							}},
						},
					},
				),
			}},
			SocketOptions: NewSocketOptions().TCPKeepalive().Build(),
		},
	})

	run(t, "metric-routes-tls-with-ca", testcase{
		address: "127.0.0.127",
		port:    8123,
		opts:    []ListenerOption{MetricsRouting(), MetricsTLS("cabundle")},
		want: &envoy_config_listener_v3.Listener{
			Name:    "stats-om-enforced",
			Address: SocketAddress("127.0.0.127", 8123),
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: protobuf.MustMarshalAny(&envoy_filter_network_http_connection_manager_v3.HttpConnectionManager{
							StatPrefix: "stats",
							RouteSpecifier: &envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
								RouteConfig: &envoy_config_route_v3.RouteConfiguration{
									VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
										Name:    "backend",
										Domains: []string{"*"},
										Routes:  []*envoy_config_route_v3.Route{route("/stats"), route("/stats/prometheus")},
									}},
								},
							},
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
				TransportSocket: DownstreamTLSTransportSocket(
					&envoy_transport_socket_tls_v3.DownstreamTlsContext{
						CommonTlsContext: &envoy_transport_socket_tls_v3.CommonTlsContext{
							TlsParams: &envoy_transport_socket_tls_v3.TlsParameters{
								TlsMinimumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
								TlsMaximumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
							},
							TlsCertificateSdsSecretConfigs: []*envoy_transport_socket_tls_v3.SdsSecretConfig{{
								Name:      "metrics-tls-certificate",
								SdsConfig: ConfigSource("contour"),
							}},
							ValidationContextType: &envoy_transport_socket_tls_v3.CommonTlsContext_ValidationContextSdsSecretConfig{
								ValidationContextSdsSecretConfig: &envoy_transport_socket_tls_v3.SdsSecretConfig{
									Name:      "metrics-ca-certificate",
									SdsConfig: ConfigSource("contour"),
								},
							},
						},
						RequireClientCertificate: wrapperspb.Bool(true),
					},
				),
			}},
			SocketOptions: NewSocketOptions().TCPKeepalive().Build(),
		},
	})

	run(t, "metrics-routes-tls-with-ca-health-ignore-om-limits", testcase{
		address: "127.0.0.127",
		port:    8123,
		opts: []ListenerOption{
			MetricsRouting(),
			MetricsTLS("cabundle"),
			HealthRouting(),
			IgnoreOverloadManagerLimits(),
		},
		want: &envoy_config_listener_v3.Listener{
			Name:    "stats-health",
			Address: SocketAddress("127.0.0.127", 8123),
			FilterChains: []*envoy_config_listener_v3.FilterChain{{
				Filters: []*envoy_config_listener_v3.Filter{{
					Name: wellknown.HTTPConnectionManager,
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: protobuf.MustMarshalAny(&envoy_filter_network_http_connection_manager_v3.HttpConnectionManager{
							StatPrefix: "stats",
							RouteSpecifier: &envoy_filter_network_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
								RouteConfig: &envoy_config_route_v3.RouteConfiguration{
									VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
										Name:    "backend",
										Domains: []string{"*"},
										Routes:  []*envoy_config_route_v3.Route{route("/ready"), route("/stats"), route("/stats/prometheus")},
									}},
								},
							},
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
				TransportSocket: DownstreamTLSTransportSocket(
					&envoy_transport_socket_tls_v3.DownstreamTlsContext{
						CommonTlsContext: &envoy_transport_socket_tls_v3.CommonTlsContext{
							TlsParams: &envoy_transport_socket_tls_v3.TlsParameters{
								TlsMinimumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
								TlsMaximumProtocolVersion: envoy_transport_socket_tls_v3.TlsParameters_TLSv1_3,
							},
							TlsCertificateSdsSecretConfigs: []*envoy_transport_socket_tls_v3.SdsSecretConfig{{
								Name:      "metrics-tls-certificate",
								SdsConfig: ConfigSource("contour"),
							}},
							ValidationContextType: &envoy_transport_socket_tls_v3.CommonTlsContext_ValidationContextSdsSecretConfig{
								ValidationContextSdsSecretConfig: &envoy_transport_socket_tls_v3.SdsSecretConfig{
									Name:      "metrics-ca-certificate",
									SdsConfig: ConfigSource("contour"),
								},
							},
						},
						RequireClientCertificate: wrapperspb.Bool(true),
					},
				),
			}},
			SocketOptions:         NewSocketOptions().TCPKeepalive().Build(),
			IgnoreGlobalConnLimit: true,
		},
	})
}
