"""Visualization module for the traffic detection system."""
from datetime import datetime
from pathlib import Path
import pandas as pd
from loguru import logger
import plotly.graph_objects as go
import plotly.express as px

class ResultVisualizer:
    """Generates visualizations and reports for the analysis results."""
    
    def __init__(self, config: dict):
        """Initialize the result visualizer.
        
        Args:
            config: Configuration dictionary for visualization.
        """
        self.config = config
        self.logger = logger.bind(module=__name__)
        self.output_dir = Path(self.config.get('output_dir', 'data/reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, all_features_df: pd.DataFrame, anomalies: list, output_file: str, summary: dict) -> str:
        """Generate a report from the analysis results.

        Args:
            all_features_df: DataFrame of all extracted features for general stats.
            anomalies: A list of dictionaries, where each dictionary contains details
                       about an anomalous session (features, score, profile snapshot).
            output_file: Base name for the output report file.
            summary: A dictionary containing the run summary statistics.

        Returns:
            Path to the generated report.
        """
        if not self.config.get('enable', True):
            self.logger.info("Visualization is disabled.")
            return ""

        report_format = self.config.get('format', 'html')
        output_path = self.output_dir / f"{output_file}.{report_format}"

        self.logger.info(f"Generating {report_format} report at {output_path}")

        if all_features_df.empty:
            self.logger.warning("Features DataFrame is empty, generating minimal report.")
            return self._generate_empty_report(output_path, output_file)
        
        anomalies_df = pd.DataFrame(anomalies)
        num_anomalies = len(anomalies_df)
        anomaly_ratio = num_anomalies / len(all_features_df) if len(all_features_df) > 0 else 0

        visualizations = {}
        try:
            self.logger.info("Generating traffic analysis visualizations...")
            visualizations['traffic_analysis'] = self._generate_traffic_analysis(all_features_df)
            visualizations['sankey'] = self._generate_sankey_diagram(all_features_df)
            visualizations['protocol_rose'] = self._generate_protocol_rose_chart(all_features_df)
        except Exception as e:
            self.logger.error(f"Error generating visualizations: {e}", exc_info=True)
            visualizations['error'] = f"<div class='error'><p>Error generating visualizations: {str(e)}</p></div>"

        summary_table = self._generate_summary_table(summary)

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Traffic Analysis Report: {output_file}</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 2em; 
                    line-height: 1.6;
                    color: #333;
                }}
                .summary, .summary-table-container {{ 
                    background-color: #f8f9fa; 
                    border: 1px solid #e9ecef; 
                    padding: 20px; 
                    border-radius: 8px;
                    margin-bottom: 2em;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .traffic-analysis {{ 
                    margin: 2em 0; 
                    padding: 1em;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                table {{ 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin: 1em 0;
                    font-size: 0.9em;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }}
                th, td {{ 
                    border: 1px solid #ddd; 
                    padding: 12px; 
                    text-align: left; 
                }}
                th {{ 
                    background-color: #f2f2f2;
                }}
            </style>
        </head>
        <body>
            <h1>Network Traffic Analysis Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="summary">
                <h2>Overall Summary</h2>
                <p><b>Total Samples Analyzed:</b> {len(all_features_df):,}</p>
                <p><b>Anomalies Detected:</b> {num_anomalies} ({anomaly_ratio:.2%})</p>
                <p><b>Time Range:</b> {all_features_df['timestamp'].min()} to {all_features_df['timestamp'].max()}</p>
            </div>

            <div class="summary-table-container">
                <h2>Processing Pipeline Summary</h2>
                {summary_table}
            </div>

            <div class="traffic-analysis">
                <h2>Traffic Analysis</h2>
                {visualizations.get('traffic_analysis', '')}
            </div>

            <h2>Detected Anomalies ({num_anomalies} found)</h2>
            {self._generate_anomaly_explanation(anomalies_df) if num_anomalies > 0 else ''}
            {anomalies_df.head(100).to_html(max_rows=100) if num_anomalies > 0 else '<p>No anomalies detected.</p>'}
        </body>
        </html>
        """

        try:
            with open(output_path, 'w') as f:
                f.write(html_content)
            self.logger.info("Report generated successfully.")
            return str(output_path)
        except Exception as e:
            self.logger.error(f"Failed to write report to {output_path}: {e}")
            return ""

    def _generate_summary_table(self, summary: dict) -> str:
        """Generates an HTML table from the summary dictionary."""
        ingestion = summary.get('ingestion_stats', {})
        session = summary.get('sessionization_stats', {})
        detection = summary.get('detection_stats', {})

        html = "<table>"
        html += "<tr><th>Stage</th><th>Metric</th><th>Value</th></tr>"
        
        # Ingestion Stats
        html += f"<tr><td rowspan='4'>Ingestion</td><td>Files Found</td><td>{ingestion.get('total_files', 0)}</td></tr>"
        html += f"<tr><td>Packets Read</td><td>{ingestion.get('total_packets_read', 0)}</td></tr>"
        html += f"<tr><td>Packets Filtered/Skipped</td><td>{ingestion.get('total_packets_read', 0) - ingestion.get('packets_successfully_processed', 0)}</td></tr>"
        html += f"<tr><td>Packets Processed</td><td>{ingestion.get('packets_successfully_processed', 0)}</td></tr>"

        # Sessionization Stats
        html += f"<tr><td rowspan='2'>Sessionization</td><td>Records Before Aggregation</td><td>{session.get('total_records_before_sessionization', 0)}</td></tr>"
        html += f"<tr><td>Unique Sessions (by src_ip)</td><td>{session.get('total_sessions_created', 0)}</td></tr>"

        # Detection Stats
        html += f"<tr><td rowspan='3'>Detection</td><td>Sessions Processed</td><td>{detection.get('sessions_processed_successfully', 0)}</td></tr>"
        html += f"<tr><td>Sessions Skipped/Failed</td><td>{detection.get('sessions_skipped_or_failed', 0)}</td></tr>"
        html += f"<tr><td>Anomalies Detected</td><td>{detection.get('anomalies_detected', 0)}</td></tr>"

        html += "</table>"
        return html

    def _generate_traffic_analysis(self, features: pd.DataFrame) -> str:
        """Generate comprehensive traffic analysis."""
        analysis = ""
        
        # Identify local host IPs
        local_ips = self._identify_local_host_ips(features)
        if not local_ips:
            return "<p>No local host traffic detected.</p>"

        # 1. Protocol Distribution (Rose Chart)
        analysis += "<div class='section'>"
        analysis += "<div class='section-header'><h3>Protocol Distribution</h3></div>"
        analysis += self._generate_protocol_rose_chart(features)
        analysis += "</div>"

        # 2. Host Traffic Analysis
        analysis += "<div class='section'>"
        analysis += "<div class='section-header'><h3>Host Traffic Analysis</h3></div>"
        analysis += "<div class='section-content'>"
        
        # Top 5 most active hosts by packet count
        src_host_activity = features.groupby('src_ip')['src_host_pkt_count_win'].sum().sort_values(ascending=False).head(5)
        dst_host_activity = features.groupby('dst_ip')['dst_host_pkt_count_win'].sum().sort_values(ascending=False).head(5)
        
        analysis += "<h4>Top 5 Most Active Source Hosts</h4>"
        analysis += "<table>"
        analysis += "<tr><th>Source IP</th><th>Total Packets</th></tr>"
        for ip, count in src_host_activity.items():
            is_local = ip in local_ips
            ip_class = "local-ip" if is_local else ""  # Add CSS class for local IPs
            analysis += f"<tr><td class='{ip_class}'>{ip}</td><td>{count}</td></tr>"
        analysis += "</table>"

        analysis += "<h4>Top 5 Most Active Destination Hosts</h4>"
        analysis += "<table>"
        analysis += "<tr><th>Destination IP</th><th>Total Packets</th></tr>"
        for ip, count in dst_host_activity.items():
            is_local = ip in local_ips
            ip_class = "local-ip" if is_local else ""
            analysis += f"<tr><td class='{ip_class}'>{ip}</td><td>{count}</td></tr>"
        analysis += "</table>"
        analysis += "</div></div>"

        # 3. Local Host Detailed Analysis
        analysis += "<div class='section'>"
        analysis += "<div class='section-header'><h3>Local Host Detailed Analysis</h3></div>"
        analysis += "<div class='section-content'>"
        
        for local_ip in local_ips:
            analysis += f"<h4>Local Host: {local_ip}</h4>"
            
            # Get interactions with this host
            local_host_data = features[(features['src_ip'] == local_ip) | (features['dst_ip'] == local_ip)]
            
            # Protocol distribution for this host
            host_protocol_dist = local_host_data['protocol'].value_counts()
            analysis += "<h5>Protocol Distribution</h5>"
            analysis += "<table>"
            analysis += "<tr><th>Protocol</th><th>Count</th><th>Percentage</th></tr>"
            for protocol, count in host_protocol_dist.items():
                percentage = (count / len(local_host_data)) * 100
                analysis += f"<tr><td>{protocol}</td><td>{count}</td><td>{percentage:.2f}%</td></tr>"
            analysis += "</table>"

            # Top 5 interactions with this host
            if local_ip in src_host_activity.index:
                src_interactions = local_host_data[local_host_data['src_ip'] == local_ip]
                top_dst = src_interactions.groupby('dst_ip').size().sort_values(ascending=False).head(5)
                analysis += "<h5>Top 5 Destination Hosts</h5>"
                analysis += "<table>"
                analysis += "<tr><th>Destination IP</th><th>Interaction Count</th><th>Protocols Used</th></tr>"
                for dst_ip, count in top_dst.items():
                    protocols = src_interactions[src_interactions['dst_ip'] == dst_ip]['protocol'].unique()
                    analysis += f"<tr><td>{dst_ip}</td><td>{count}</td><td>{', '.join(protocols)}</td></tr>"
                analysis += "</table>"

            if local_ip in dst_host_activity.index:
                dst_interactions = local_host_data[local_host_data['dst_ip'] == local_ip]
                top_src = dst_interactions.groupby('src_ip').size().sort_values(ascending=False).head(5)
                analysis += "<h5>Top 5 Source Hosts</h5>"
                analysis += "<table>"
                analysis += "<tr><th>Source IP</th><th>Interaction Count</th><th>Protocols Used</th></tr>"
                for src_ip, count in top_src.items():
                    protocols = dst_interactions[dst_interactions['src_ip'] == src_ip]['protocol'].unique()
                    analysis += f"<tr><td>{src_ip}</td><td>{count}</td><td>{', '.join(protocols)}</td></tr>"
                analysis += "</table>"

        # 3. Protocol Analysis
        analysis += "<div class='section'>"
        analysis += "<div class='section-header'><h3>Protocol Analysis</h3></div>"
        
        # Add protocol statistics without the chart
        protocol_counts = features['protocol'].value_counts().reset_index()
        protocol_counts.columns = ['Protocol', 'Count']
        protocol_stats = protocol_counts.to_html(index=False, classes='dataframe', border=0)
        
        analysis += f"<div class='protocol-stats'>{protocol_stats}</div>"
        analysis += "<p>Note: The protocol distribution chart is available in the main visualization section below.</p>"
        analysis += "</div>"
        
        # Close the last section
        analysis += "</div>"
        
        return analysis

    def _identify_local_host_ips(self, features: pd.DataFrame) -> list:
        """Identify local host IPs based on traffic patterns."""
        # Local hosts are typically:
        # 1. Most active hosts
        # 2. Hosts with bidirectional traffic
        # 3. Hosts that appear both as source and destination
        
        # Get top active hosts
        src_host_activity = features.groupby('src_ip')['src_host_pkt_count_win'].sum()
        dst_host_activity = features.groupby('dst_ip')['dst_host_pkt_count_win'].sum()
        
        # Find hosts that are both source and destination
        all_ips = set(src_host_activity.index) | set(dst_host_activity.index)
        bidirectional_ips = []
        
        for ip in all_ips:
            is_src = ip in src_host_activity.index
            is_dst = ip in dst_host_activity.index
            if is_src and is_dst:
                bidirectional_ips.append(ip)
        
        # Sort by total activity to get the most active bidirectional host
        if bidirectional_ips:
            total_activity = src_host_activity.add(dst_host_activity, fill_value=0)
            local_ips = [ip for ip in bidirectional_ips if ip in total_activity.index]
            local_ips.sort(key=lambda x: total_activity[x], reverse=True)
            return local_ips[:1]  # Return the most active one as local host
        
        return []

    def _generate_sankey_diagram(self, features: pd.DataFrame, top_n=10) -> str:
        self.logger.info("Generating Sankey diagram...")
        try:
            if 'src_ip' not in features.columns or 'dst_ip' not in features.columns:
                return ""

            # Identify the primary host IP (the one sending the most packets)
            main_host_ip = features['src_ip'].mode()[0]
            self.logger.info(f"Identified main host IP for Sankey diagram: {main_host_ip}")

            # Filter for flows originating from the main host
            host_flows = features[features['src_ip'] == main_host_ip]
            flow_counts = host_flows.groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
            flow_counts = flow_counts.nlargest(top_n, 'count')

            if flow_counts.empty:
                return "<p>No outbound traffic from the main host to display.</p>"

            # Create nodes and links for the Sankey diagram
            all_ips = pd.concat([flow_counts['src_ip'], flow_counts['dst_ip']]).unique()
            ip_map = {ip: i for i, ip in enumerate(all_ips)}

            # Create labels with hostnames if available
            labels = []
            use_hostnames = 'src_hostname' in features.columns and 'dst_hostname' in features.columns

            if use_hostnames:
                self.logger.info("Using hostnames for Sankey diagram labels.")
                for ip in all_ips:
                    try:
                        if ip == main_host_ip:
                            hostname = features[features['src_ip'] == ip]['src_hostname'].iloc[0]
                            labels.append(f"{ip} (host)" if pd.notna(hostname) else f"{ip} (host)")
                        else:
                            hostname = features[features['dst_ip'] == ip]['dst_hostname'].iloc[0]
                            labels.append(hostname if pd.notna(hostname) else ip)
                    except IndexError:
                        labels.append(ip) # Fallback if IP not found
            else:
                self.logger.warning("Hostname columns not found. Falling back to IP addresses for Sankey labels.")
                labels = list(all_ips)

            fig = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=labels,
                    color="#3498db"
                ),
                link=dict(
                    source=[ip_map[src] for src in flow_counts['src_ip']],
                    target=[ip_map[dst] for dst in flow_counts['dst_ip']],
                    value=flow_counts['count'],
                    color="rgba(0,0,0,0.2)"
                ))])

            fig.update_layout(title_text=f"Top {top_n} Outbound Flows from {main_host_ip}", font_size=12)
            self.logger.info("Sankey diagram generated successfully.")
            return fig.to_html(full_html=False, include_plotlyjs='cdn')
        except Exception as e:
            self.logger.error(f"Failed to generate Sankey diagram: {e}")
            return "<p>Error generating Sankey diagram.</p>"

    def _generate_protocol_rose_chart(self, features: pd.DataFrame) -> str:
        self.logger.info("Generating protocol rose chart...")
        try:
            if 'protocol' not in features.columns:
                return ""
                
            protocol_dist = features['protocol'].value_counts().reset_index()
            protocol_dist.columns = ['protocol', 'count']

            fig = px.bar_polar(protocol_dist, r='count', theta='protocol',
                               color='count', template='seaborn',
                               title="Protocol Distribution",
                               color_discrete_sequence=px.colors.sequential.Plasma_r)
            fig.update_layout(polar=dict(radialaxis=dict(showticklabels=False, ticks='')))
            self.logger.info("Protocol rose chart generated successfully.")
            return fig.to_html(full_html=False, include_plotlyjs='cdn')
        except Exception as e:
            self.logger.error(f"Failed to generate protocol rose chart: {e}")
            return "<p>Error generating protocol rose chart.</p>"

    def _generate_anomaly_explanation(self, anomalies: pd.DataFrame) -> str:
        """Generate a textual explanation for the detected anomalies."""
        if anomalies.empty:
            return ""

        explanation = "<h3>Anomaly Interpretation</h3>"
        explanation += "<p>The detected anomalies exhibit the following characteristics, which distinguish them from normal traffic:</p>"
        explanation += "<ul>"

        # Check for extreme values in key columns
        if 'flow_duration_seconds' in anomalies.columns and (anomalies['flow_duration_seconds'] < 1e-6).any():
            explanation += "<li><b>Extremely Short Flow Duration:</b> Some flows were completed in microseconds or nanoseconds. This is highly unusual and results in calculated data rates that are physically impossible, marking them as statistical outliers.</li>"

        if 'flow_bytes_per_sec' in anomalies.columns and anomalies['flow_bytes_per_sec'].max() > 1e9:  # > 1 GB/s
            explanation += "<li><b>Astronomical Data Rates:</b> The calculated data rates (bytes/sec) are exceedingly high. This is a direct consequence of the extremely short flow durations and is a strong indicator of an anomaly.</li>"

        if 'src_host_pkt_count_win' in anomalies.columns and anomalies['src_host_pkt_count_win'].max() > 100:
            explanation += "<li><b>High Packet Count from a Single Host:</b> Certain source IPs generated a very high number of packets in a short time window, which could be indicative of scanning behavior or a data burst.</li>"

        explanation += "</ul>"
        explanation += """<p><b>Conclusion:</b> These events are flagged as anomalies primarily due to their extreme statistical properties, 
        particularly related to timing and calculated rates, rather than specific malicious content. This could point to data processing artifacts, 
        network configuration issues, or genuine but rare network events.</p>

        <p>For a deeper dive, please examine the detailed anomaly table below. The features that most significantly contributed to the anomaly score are highlighted.</p>

        <p><b>Note:</b> The term 'anomaly' does not necessarily imply malicious activity but rather a deviation from the established baseline of 'normal' traffic. 
        Further investigation is often required to determine the root cause.</p>
        
        <p><i>This automated analysis provides a high-level overview. For critical systems, always correlate these findings with other security logs and contextual information.</i></p>"""
        return explanation

    def _generate_anomaly_details_view(self, anomalies: list) -> str:
        """Generate a detailed side-by-side comparison for each anomaly."""
        if not anomalies:
            return ""

        html = "<div class='anomaly-details-container'>"

        for i, anomaly in enumerate(anomalies):
            features = anomaly['features']
            profile = anomaly['profile_snapshot']
            score = anomaly['anomaly_score']
            ip = features.get('client_ip', 'N/A')

            # --- Current Session Table ---
            current_session_html = "<table class='comparison-table'><tr><th colspan='2'>Current Session</th></tr>"
            for key, val in features.items():
                row_class = 'highlight' if 'is_new' in key and val == 1 else ''
                current_session_html += f"<tr class='{row_class}'><td>{key}</td><td>{val}</td></tr>"
            current_session_html += "</table>"

            # --- Historical Profile Table ---
            if profile:
                historical_profile_html = "<table class='comparison-table'><tr><th colspan='2'>Historical Profile</th></tr>"
                # Sort profile for consistent display
                sorted_profile_items = sorted(profile.items())
                for key, val in sorted_profile_items:
                    if isinstance(val, set) or isinstance(val, list):
                        val_str = ', '.join(map(str, val)) if val else 'None'
                        if len(val_str) > 100: # Truncate long lists
                           val_str = val_str[:100] + '...'
                    else:
                        val_str = str(val)
                    historical_profile_html += f"<tr><td>{key}</td><td>{val_str}</td></tr>"
                historical_profile_html += "</table>"
            else:
                historical_profile_html = "<div class='profile-note'>No historical profile available (first time seeing this IP).</div>"

            # --- Assemble Card ---
            html += f"""
            <div class='anomaly-card'>
                <h3 class='anomaly-title'>Anomaly #{i+1}: IP Address {ip} (Score: {score:.4f})</h3>
                <div class='comparison-container'>
                    <div>{current_session_html}</div>
                    <div>{historical_profile_html}</div>
                </div>
            </div>
            """

        html += "</div>"
        return html

    def _generate_empty_report(self, output_path: Path, output_file: str) -> str:
        """Generate a minimal report when no data is available."""
        html_content = f"""
        <html>
        <head>
            <title>Traffic Analysis Report: {output_file}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 2em; }}
                .warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <h1>Traffic Anomaly Detection Report</h1>
            <div class="warning">
                <h3>No Data Available</h3>
                <p>No traffic data was processed for analysis. Please check:</p>
                <ul>
                    <li>PCAP files are present in the input directory</li>
                    <li>PCAP files are not corrupted</li>
                    <li>Display filters are not too restrictive</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        try:
            with open(output_path, 'w') as f:
                f.write(html_content)
            self.logger.info("Empty report generated successfully.")
            return str(output_path)
        except Exception as e:
            self.logger.error(f"Failed to write empty report: {e}")
            return ""

    def _generate_basic_report(self, output_path: Path, output_file: str, features: pd.DataFrame) -> str:
        """Generate a basic report when predictions are unavailable."""
        total_packets = len(features)
        
        html_content = f"""
        <html>
        <head>
            <title>Traffic Analysis Report: {output_file}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 2em; }}
                .info {{ background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 4px; }}
                table {{ border-collapse: collapse; width: 80%; margin: 1em 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Traffic Analysis Report</h1>
            <div class="info">
                <h3>Basic Traffic Summary</h3>
                <p><b>Total Packets Analyzed:</b> {total_packets}</p>
                <p><b>Status:</b> Anomaly detection was not performed due to model issues.</p>
            </div>
            
            <h2>Traffic Overview</h2>
            {features.describe().to_html() if not features.empty else '<p>No traffic data available.</p>'}
        </body>
        </html>
        """
        
        try:
            with open(output_path, 'w') as f:
                f.write(html_content)
            self.logger.info("Basic report generated successfully.")
            return str(output_path)
        except Exception as e:
            self.logger.error(f"Failed to write basic report: {e}")
            return ""