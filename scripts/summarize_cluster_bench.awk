function value(name, fallback,    i, pair) {
    for (i = 1; i <= NF; i++) {
        split($i, pair, "=")
        if (pair[1] == name) {
            return pair[2]
        }
    }
    return fallback
}

$1 == "E2E_BENCH_RESULT" {
    result_nodes++
    runs = value("runs", 0) + 0
    success_runs = value("success_runs", 0) + 0
    attempt = value("mean_all_latency_ms", 0) + 0
    if (attempt > max_attempt_latency) {
        max_attempt_latency = attempt
    }
    if (runs <= 0 || success_runs < runs) {
        next
    }

    successful_nodes++
    protocol_sent_sum += value("mean_total_sent_bytes", 0) + 0
    arc_share_sent_sum += value("mean_arc_share_sent_bytes", 0) + 0
    latency[successful_nodes] = value("mean_latency_ms", 0) + 0
    setup_latency[successful_nodes] = value("mean_setup_ms", 0) + 0
    barrier_latency[successful_nodes] = value("mean_recover_barrier_wait_ms", 0) + 0
    sent_bytes[successful_nodes] = value("mean_total_sent_bytes", 0) + 0
    recv_bytes[successful_nodes] = value("mean_total_recv_bytes", 0) + 0
    arc_share_bytes[successful_nodes] = value("mean_arc_share_sent_bytes", 0) + 0
    latency_sum += latency[successful_nodes]
    setup_sum += value("mean_setup_ms", 0) + 0
    sent_sum += value("mean_total_sent_bytes", 0) + 0
    recv_sum += value("mean_total_recv_bytes", 0) + 0
    hash = value("consensus_hash", "")
    if (hash != "" && hash != "none") {
        consensus[hash] = 1
    }
}

END {
    for (i = 1; i <= successful_nodes; i++) {
        for (j = i + 1; j <= successful_nodes; j++) {
            if (latency[j] < latency[i]) {
                tmp = latency[i]
                latency[i] = latency[j]
                latency[j] = tmp
                tmp = setup_latency[i]
                setup_latency[i] = setup_latency[j]
                setup_latency[j] = tmp
                tmp = barrier_latency[i]
                barrier_latency[i] = barrier_latency[j]
                barrier_latency[j] = tmp
                tmp = sent_bytes[i]
                sent_bytes[i] = sent_bytes[j]
                sent_bytes[j] = tmp
                tmp = recv_bytes[i]
                recv_bytes[i] = recv_bytes[j]
                recv_bytes[j] = tmp
                tmp = arc_share_bytes[i]
                arc_share_bytes[i] = arc_share_bytes[j]
                arc_share_bytes[j] = tmp
            }
        }
    }

    quorum = expected_nodes - faults
    quorum_success = successful_nodes >= quorum ? 1 : 0
    all_success = successful_nodes >= expected_nodes ? 1 : 0
    quorum_latency = quorum_success ? latency[quorum] : -1
    quorum_online_latency = quorum_success ? latency[quorum] - setup_latency[quorum] - barrier_latency[quorum] : -1
    if (quorum_online_latency < 0) {
        quorum_online_latency = 0
    }
    all_latency = all_success ? latency[expected_nodes] : -1
    mean_latency = successful_nodes > 0 ? latency_sum / successful_nodes : 0
    mean_setup = successful_nodes > 0 ? setup_sum / successful_nodes : 0
    mean_sent = successful_nodes > 0 ? sent_sum / successful_nodes : 0
    mean_recv = successful_nodes > 0 ? recv_sum / successful_nodes : 0
    quorum_sent_sum = 0
    quorum_recv_sum = 0
    quorum_arc_share_sum = 0
    if (quorum_success) {
        for (i = 1; i <= quorum; i++) {
            quorum_sent_sum += sent_bytes[i]
            quorum_recv_sum += recv_bytes[i]
            quorum_arc_share_sum += arc_share_bytes[i]
        }
    }
    quorum_mean_sent = quorum_success ? quorum_sent_sum / quorum : 0
    quorum_mean_recv = quorum_success ? quorum_recv_sum / quorum : 0
    consensus_hashes = 0
    quorum_arc_share_valid = quorum_success && quorum_sent_sum > 0 ? 1 : 0
    quorum_arc_communication_share = quorum_arc_share_valid ? 100 * quorum_arc_share_sum / quorum_sent_sum : -1
    for (hash in consensus) {
        consensus_hashes++
    }

    printf("CLUSTER_BENCH_RESULT protocol=%s expected_nodes=%d result_nodes=%d successful_nodes=%d quorum=%d quorum_success=%d all_success=%d quorum_latency_ms=%.2f quorum_online_latency_ms=%.2f all_nodes_latency_ms=%.2f mean_node_latency_ms=%.2f max_attempt_latency_ms=%.2f mean_setup_ms=%.2f mean_sent_bytes_per_node=%.0f mean_recv_bytes_per_node=%.0f quorum_mean_sent_bytes_per_node=%.0f quorum_mean_recv_bytes_per_node=%.0f mean_sent_bytes_all_success=%.0f mean_recv_bytes_all_success=%.0f total_protocol_sent_bytes=%.0f total_arc_share_sent_bytes=%.0f quorum_protocol_sent_bytes=%.0f quorum_arc_share_sent_bytes=%.0f arc_communication_nodes=%d arc_communication_share_valid=%d arc_communication_share_pct=%.6f arc_communication_share_all_success_valid=%d arc_communication_share_all_success_pct=%.6f consensus_hashes=%d\n",
        protocol, expected_nodes, result_nodes, successful_nodes, quorum,
        quorum_success, all_success, quorum_latency, quorum_online_latency, all_latency, mean_latency,
        max_attempt_latency, mean_setup, mean_sent, mean_recv, quorum_mean_sent, quorum_mean_recv, mean_sent, mean_recv,
        protocol_sent_sum, arc_share_sent_sum, quorum_sent_sum, quorum_arc_share_sum, quorum,
        quorum_arc_share_valid, quorum_arc_communication_share, (protocol_sent_sum > 0 ? 1 : 0),
        (protocol_sent_sum > 0 ? 100 * arc_share_sent_sum / protocol_sent_sum : -1), consensus_hashes)
}
