import inspect

import plugins.deception.app.equifax_baseline_v2 as equifax
import plugins.deception.app.greedy as greedy
import plugins.deception.app.random as random

import plugins.deception.app.actions.LowLevelAction as LowLevelAction
import plugins.deception.app.actions.LowLevel as LowLevel

# Knowledge modules
import plugins.deception.app.actions.Information.KnowledgeBase as KnowledgeBase
import plugins.deception.app.actions.Information.Network as Network
import plugins.deception.app.actions.Information.Subnet as Subnet
import plugins.deception.app.actions.Information.Host as Host
import plugins.deception.app.actions.Information.Credential as Credential
import plugins.deception.app.actions.Information.InfectionTree as InfectionTree


from plugins.deception.app.actions.HighLevel import (
    Scan,
    DiscoverHostInformation,
    LateralMoveToHost,
    SmartExfiltrateData,
)

from rich import print


def count_lines_in_high_level_action(high_level_action, low_level_actions):
    lines = get_function_semantic_lines(high_level_action)
    total_lines = 0

    for line in lines:
        low_level_function = None

        for key, value in low_level_actions.items():
            if (key + ".run") in line:
                total_lines += value
                low_level_function = key
                break

        if not low_level_function:
            total_lines += 1

    return total_lines


def count_lines_in_low_level_action(low_level_action):
    add_fact_lines = len(
        get_function_semantic_lines(LowLevelAction.LowLevelAction.add_fact)
    )
    remove_fact_lines = len(
        get_function_semantic_lines(LowLevelAction.LowLevelAction.remove_fact)
    )

    # Create facts counter
    create_facts_lines = 0
    for line in get_function_semantic_lines(low_level_action.create_facts):
        if "await self.add_fact" in line:
            create_facts_lines += add_fact_lines
        else:
            create_facts_lines += 1

    # Remove facts counter
    reset_facts_lines = 0
    for line in get_function_semantic_lines(low_level_action.reset_facts):
        if "await self.remove_fact" in line:
            reset_facts_lines += remove_fact_lines
        else:
            reset_facts_lines += 1

    # Get result counter
    get_result_lines = len(get_function_semantic_lines(low_level_action.get_result))

    return create_facts_lines + reset_facts_lines + get_result_lines


def get_function_semantic_lines(functions):
    if not isinstance(functions, list):
        functions = [functions]

    semantic_lines = []
    for func in functions:
        lines = inspect.getsourcelines(func)
        semantic_lines += count_semantic_lines(lines[0])

    return semantic_lines


def count_semantic_lines(lines):
    semantic_lines = []
    for line in lines:
        if line.strip().startswith("#"):
            continue
        if "log_event" in line.strip():
            continue
        if line.strip() == "":
            continue
        if line.strip() == "\n":
            continue

        semantic_lines.append(line)
    return semantic_lines


def count_saved_lines(lines, high_level_actions):
    saved_lines = 0
    for line in lines:
        for key, value in high_level_actions.items():
            if (key + ".run") in line:
                saved_lines += value
                break
    return saved_lines


def print_result(strategy_name, lines, high_level_actions):
    perry_lines = len(lines)
    saved_lines = count_saved_lines(lines, high_level_actions)
    caldera_lines = perry_lines + saved_lines

    print(f"### {strategy_name} ###")
    print(f"Lines in Perry: {perry_lines}")
    print(f"Lines in Caldera: {caldera_lines}")
    print(f"Saved lines: {saved_lines}")


def count_parse_event_lines(lines):
    parse_event_lines = 0
    for line in lines:
        if "parse_events" in line:
            parse_event_lines += 1
    return parse_event_lines


if __name__ == "__main__":
    low_level_actions = {
        "findSSHConfigAction": count_lines_in_low_level_action(LowLevel.FindSSHConfig),
        "listFilesInDirAction": count_lines_in_low_level_action(
            LowLevel.ListFilesInDirectory
        ),
        "readFileAction": count_lines_in_low_level_action(LowLevel.ReadFile),
        "scpAction": count_lines_in_low_level_action(LowLevel.SCPFile),
        "wgetAction": count_lines_in_low_level_action(LowLevel.wgetFile),
        "md5Action": count_lines_in_low_level_action(LowLevel.MD5SumAttackerData),
        "exploitStrutsAction": count_lines_in_low_level_action(LowLevel.ExploitStruts),
        "sshLateralMoveAction": count_lines_in_low_level_action(
            LowLevel.SSHLateralMove
        ),
        "scanHostAction": count_lines_in_low_level_action(LowLevel.ScanHost),
        "scanNetworkAction": count_lines_in_low_level_action(LowLevel.ScanNetwork),
    }

    high_level_actions = {
        "scanAction": count_lines_in_high_level_action(Scan.run, low_level_actions),
        "discoverInfoAction": count_lines_in_high_level_action(
            DiscoverHostInformation.run, low_level_actions
        ),
        "infectHostAction": count_lines_in_high_level_action(
            LateralMoveToHost.run, low_level_actions
        ),
        "exfiltrateDataAction": count_lines_in_high_level_action(
            SmartExfiltrateData.run, low_level_actions
        ),
    }

    equifax_functions = [
        equifax.LogicalPlanner.main,
        equifax.LogicalPlanner.initial_access,
        equifax.LogicalPlanner.cred_exfiltrate,
    ]

    greedy_functions = [
        greedy.LogicalPlanner.main,
        greedy.LogicalPlanner.initial_access,
        greedy.LogicalPlanner.greedy_spread,
    ]

    random_functions = [
        random.LogicalPlanner.main,
        random.LogicalPlanner.initial_access,
        random.LogicalPlanner.random_spread,
    ]

    equifax_lines = get_function_semantic_lines(equifax_functions)
    greedy_lines = get_function_semantic_lines(greedy_functions)
    random_lines = get_function_semantic_lines(random_functions)

    print_result("Equifax", equifax_lines, high_level_actions)
    print_result("Greedy", greedy_lines, high_level_actions)
    print_result("Random", random_lines, high_level_actions)

    print("### Low Level Actions ###")
    print(low_level_actions)

    print("### High Level Actions ###")
    print(high_level_actions)

    print("### LOC of knowledge base ###")
    knowledge_base_lines = get_function_semantic_lines(KnowledgeBase.KnowledgeBase)
    network_lines = get_function_semantic_lines(Network)
    subnet_lines = get_function_semantic_lines(Subnet)
    host_lines = get_function_semantic_lines(Host)
    credential_lines = get_function_semantic_lines(Credential)
    infection_tree_lines = get_function_semantic_lines(InfectionTree)

    static_lines = (
        len(network_lines)
        + len(subnet_lines)
        + len(host_lines)
        + len(credential_lines)
        + len(infection_tree_lines)
    )

    print(f"KnowledgeBase: {len(knowledge_base_lines)}")
    print(f"Static KnowledgeBase: {static_lines}")

    print("### LOC of parse_events ###")
    print(f"Equifax parse_events: {count_parse_event_lines(equifax_lines)}")
    print(f"Greedy parse_events: {count_parse_event_lines(greedy_lines)}")
    print(f"Random parse_events: {count_parse_event_lines(random_lines)}")
