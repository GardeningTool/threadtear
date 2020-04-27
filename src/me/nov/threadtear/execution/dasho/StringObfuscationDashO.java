package me.nov.threadtear.execution.dasho;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import me.nov.threadtear.analysis.stack.ConstantTracker;
import me.nov.threadtear.analysis.stack.ConstantValue;
import me.nov.threadtear.analysis.stack.IConstantReferenceHandler;
import me.nov.threadtear.execution.Execution;
import me.nov.threadtear.execution.ExecutionCategory;
import me.nov.threadtear.execution.ExecutionTag;
import me.nov.threadtear.io.Clazz;
import me.nov.threadtear.util.Strings;
import me.nov.threadtear.util.asm.Access;
import me.nov.threadtear.util.asm.Instructions;
import me.nov.threadtear.vm.IVMReferenceHandler;
import me.nov.threadtear.vm.Sandbox;
import me.nov.threadtear.vm.VM;

public class StringObfuscationDashO extends Execution implements IVMReferenceHandler, IConstantReferenceHandler {

	private static final String DASHO_DECRPYTION_METHOD_DESC1 = "(ILjava/lang/String;)Ljava/lang/String;";
	private static final String DASHO_DECRPYTION_METHOD_DESC2 = "(Ljava/lang/String;I)Ljava/lang/String;";

	private Map<String, Clazz> classes;
	private int encrypted;
	private int decrypted;
	private boolean verbose;

	public StringObfuscationDashO() {
		super(ExecutionCategory.DASHO, "String obfuscation removal", "Tested on version 10.3, should work for older versions too.", ExecutionTag.RUNNABLE, ExecutionTag.POSSIBLY_MALICIOUS);
	}

	@Override
	public boolean execute(Map<String, Clazz> classes, boolean verbose) {
		this.verbose = verbose;
		this.classes = classes;
		this.encrypted = 0;
		this.decrypted = 0;

		classes.values().stream().map(c -> c.node).forEach(this::decrypt);
		if (encrypted == 0) {
			logger.severe("No strings matching DashO 7.3 string obfuscation have been found!");
			return false;
		}
		float decryptionRatio = Math.round((decrypted / (float) encrypted) * 100);
		logger.info("Of a total " + encrypted + " encrypted strings, " + (decryptionRatio) + "% were successfully decrypted");
		return decryptionRatio > 0.25;
	}

	private void decrypt(ClassNode cn) {

		cn.methods.forEach(m -> {
			Analyzer<ConstantValue> a = new Analyzer<ConstantValue>(new ConstantTracker(this, Access.isStatic(m.access), m.maxLocals, m.desc, new Object[0]));
			try {
				a.analyze(cn.name, m);
			} catch (AnalyzerException e) {
				if (verbose) {
					e.printStackTrace();
				}
				logger.severe("Failed stack analysis in " + cn.name + "." + m.name + ":" + e.getMessage());
				return;
			}
			Frame<ConstantValue>[] frames = a.getFrames();
			InsnList rewrittenCode = new InsnList();
			Map<LabelNode, LabelNode> labels = Instructions.cloneLabels(m.instructions);

			// as we can't add instructions because frame index and instruction index
			// wouldn't fit together anymore we have to do it this way
			for (int i = 0; i < m.instructions.size(); i++) {
				AbstractInsnNode ain = m.instructions.get(i);
				Frame<ConstantValue> frame = frames[i];
				for (AbstractInsnNode newInstr : tryReplaceMethods(cn, m, ain, frame)) {
					rewrittenCode.add(newInstr.clone(labels));
				}
			}
			Instructions.updateInstructions(m, labels, rewrittenCode);
		});
	}

	private AbstractInsnNode[] tryReplaceMethods(ClassNode cn, MethodNode m, AbstractInsnNode ain, Frame<ConstantValue> frame) {
		if (ain.getOpcode() == INVOKESTATIC) {
			MethodInsnNode min = (MethodInsnNode) ain;
			if (min.desc.equals(DASHO_DECRPYTION_METHOD_DESC1) || min.desc.equals(DASHO_DECRPYTION_METHOD_DESC2)) {
				try {
					encrypted++;
					ConstantValue second = frame.getStack(frame.getStackSize() - 2);
					ConstantValue top = frame.getStack(frame.getStackSize() - 1);
					if (top.isKnown() && second.isKnown()) {
						// strings are not high utf and no high sdev, don't check
						String realString = invokeProxy(cn, m, min, top, second);
						if (realString != null) {
							if (Strings.isHighUTF(realString)) {
								logger.warning("String may have not decrypted correctly in " + cn.name + "." + m.name + m.desc);
							}
							this.decrypted++;
							return new AbstractInsnNode[] { new InsnNode(POP2), new LdcInsnNode(realString) };
						} else {
							logger.severe("Failed to decrypt string in " + cn.name + "." + m.name + m.desc);
						}
					} else if (verbose) {
						logger.warning("Unknown top stack value in " + cn.name + "." + m.name + m.desc + ", skipping");
					}
				} catch (Throwable e) {
					e.printStackTrace();
					logger.severe("Failed to decrypt string in " + cn.name + "." + m.name + m.desc + ": " + e.getClass().getName() + ", " + e.getMessage());
				}
			}
		}
		return new AbstractInsnNode[] { ain };
	}

	private String invokeProxy(ClassNode cn, MethodNode m, MethodInsnNode min, ConstantValue top, ConstantValue second) throws Exception {
		VM vm = VM.constructNonInitializingVM(this);
		createFakeClone(cn, m, min, top, second); // create a duplicate of the current class,
		// we need this because stringer checks for stacktrace method name and class

		ClassNode decryptionMethodOwner = classes.get(min.owner).node;
		if (decryptionMethodOwner == null)
			return null;
		vm.explicitlyPreloadWithClinit(fakeInvocationClone); // proxy class can't contain code in clinit other than the one we want to run
		if (!vm.isLoaded(decryptionMethodOwner.name.replace('/', '.'))) // decryption class could be the same class
			vm.explicitlyPreloadNoClinitAndIsolate(decryptionMethodOwner, (name, desc) -> !name.matches("java/lang/.*"));
		Class<?> loadedClone = vm.loadClass(fakeInvocationClone.name.replace('/', '.'), true); // load dupe class

		if (m.name.equals("<init>")) {
			loadedClone.newInstance(); // special case: constructors have to be invoked by newInstance.
			// Sandbox.createMethodProxy automatically handles access and super call
		} else {
			for (Method reflectionMethod : loadedClone.getMethods()) {
				if (reflectionMethod.getName().equals(m.name)) {
					reflectionMethod.invoke(null);
					break;
				}
			}
		}
		return (String) loadedClone.getDeclaredField("proxyReturn").get(null);
	}

	private void createFakeClone(ClassNode cn, MethodNode m, MethodInsnNode min, ConstantValue top, ConstantValue second) {
		ClassNode node = Sandbox.createClassProxy(cn.name);
		InsnList instructions = new InsnList();
		instructions.add(new LdcInsnNode(second.getValue()));
		instructions.add(new LdcInsnNode(top.getValue()));
		instructions.add(min.clone(null)); // we can clone original method here
		instructions.add(new FieldInsnNode(PUTSTATIC, node.name, "proxyReturn", "Ljava/lang/String;"));
		instructions.add(new InsnNode(RETURN));

		node.fields.add(new FieldNode(ACC_PUBLIC | ACC_STATIC, "proxyReturn", "Ljava/lang/String;", null, null));
		node.methods.add(Sandbox.createMethodProxy(instructions, m.name, "()V")); // method should return real string
		if (min.owner.equals(cn.name)) {
			// decryption method is in own class
			node.methods.add(Sandbox.copyMethod(getMethod(classes.get(min.owner).node, min.name, min.desc)));
		}
		fakeInvocationClone = node;
	}

	private ClassNode fakeInvocationClone;

	@Override
	public ClassNode tryClassLoad(String name) {
		if (name.equals(fakeInvocationClone.name)) {
			return fakeInvocationClone;
		}
		return classes.containsKey(name) ? classes.get(name).node : null;
	}

	@Override
	public Object getFieldValueOrNull(BasicValue v, String owner, String name, String desc) {
		return null;
	}

	@Override
	public Object getMethodReturnOrNull(BasicValue v, String owner, String name, String desc, List<? extends ConstantValue> values) {
		return null;
	}
}