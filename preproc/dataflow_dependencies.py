import angr

# Load the project
b = angr.Project("fauxware", load_options={"auto_load_libs": False})

# Generate a CFG first. In order to generate data dependence graph afterwards, you'll have to:
# - keep all input states by specifying keep_state=True.
# - store memory, register and temporary values accesses by adding the angr.options.refs option set.
# Feel free to provide more parameters (for example, context_sensitivity_level) for CFG
# recovery based on your needs.
cfg = b.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs, context_sensitivity_level=2)

# Generate the control dependence graph
cdg = b.analyses.CDG(cfg)

# Build the data dependence graph
ddg = b.analyses.DDG(cfg)

# Find the function
target_func = cfg.kb.functions.function(name="authenticate")
# We need the CFGNode instance
target_node = cfg.model.get_any_node(target_func.addr)

# Let's get a BackwardSlice out of them!
# ``targets`` is a list of objects, where each one is either a CodeLocation
# object, or a tuple of CFGNode instance and a statement ID. Setting statement
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not
# have any statement, so you should always specify -1 for it.

bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

# Get the AnnotatedCFG from the backward slice
acfg = bs.annotated_cfg()

# The only way to get addresses with the API is to iterate over all known basic blocks (from the full CFG)
# and check which ones are in the whitelist (i.e., part of the slice)

funcs_in_slice = set()

for func in cfg.kb.functions.values():
    for block in func.blocks:
        if acfg.get_whitelisted_statements(block.addr) is not None:
            funcs_in_slice.add(func.name)
            break  # No need to keep checking more blocks from this function

# Print the function names
print("Functions in the backward slice of 'authenticate':")
for name in sorted(funcs_in_slice):
    print(name)


    # Get the AnnotatedCFG from the backward slice
acfg = bs.annotated_cfg()

# Get the 'main' function from the knowledge base
main_func = cfg.kb.functions.function(name='main')

# Count how many of main's blocks are in the backward slice
count = 0
for block in main_func.blocks:
    if acfg.get_whitelisted_statements(block.addr) is not None:
        count += 1

print(f"Number of basic blocks in 'main' that appear in the backward slice of 'authenticate': {count}")
