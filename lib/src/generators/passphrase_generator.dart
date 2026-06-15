import 'dart:math';
import 'package:password_guard/src/generators/secure_random.dart';

/// Generates secure, readable, easy-to-remember passphrases.
///
/// Uses a curated internal list of 512 clean English words. Since the pool
/// size is exactly 512 (2^9), each word provides exactly 9 bits of entropy.
///
/// Example:
/// ```dart
/// // Generates a phrase like: "apple-beach-cloud-flute"
/// final phrase = PassphraseGenerator.generate();
///
/// // Get entropy of a passphrase configuration
/// final bits = PassphraseGenerator.calculateEntropy(wordCount: 5); // 45.0 bits
/// ```
class PassphraseGenerator {
  PassphraseGenerator._();

  /// Default list of 512 short, distinct, easy-to-remember English words.
  /// Each word provides exactly 9 bits of entropy (2^9 = 512).
  static const List<String> defaultWordList = [
    'about', 'above', 'actor', 'acute', 'admit', 'adopt', 'adult', 'after',
    'agent', 'agree', 'ahead', 'alarm', 'album', 'alert', 'alike', 'alive',
    'allow', 'alone', 'along', 'alter', 'amber', 'amuse', 'anchor', 'angel',
    'anger', 'angle', 'angry', 'animal', 'ankle', 'annoy', 'apart', 'appeal',
    'apple', 'apron', 'arena', 'argue', 'arise', 'armor', 'arrow', 'artist',
    'ascot', 'aspect', 'assist', 'assume', 'astray', 'atomic', 'attack', 'attic',
    'audio', 'audit', 'avatar', 'avoid', 'awake', 'award', 'aware', 'awful',
    'baboon', 'baby', 'back', 'bacon', 'badge', 'baffle', 'bagel', 'baggage',
    'baked', 'baker', 'balance', 'ball', 'ballet', 'balloon', 'bamboo', 'banana',
    'band', 'bandage', 'bang', 'banish', 'banjo', 'bank', 'banner', 'baron',
    'barrel', 'barrier', 'basket', 'basin', 'battery', 'battle', 'beach', 'beacon',
    'bead', 'beak', 'beam', 'bean', 'bear', 'beast', 'beauty', 'bedrock',
    'beef', 'beer', 'beetle', 'beggar', 'behind', 'behold', 'belief', 'bell',
    'belly', 'belong', 'below', 'belt', 'bench', 'bendy', 'benefit', 'berry',
    'berth', 'beside', 'best', 'betray', 'better', 'between', 'beyond', 'bicycle',
    'bidder', 'biggest', 'bike', 'biker', 'billet', 'billiards', 'billion', 'binder',
    'bingo', 'biology', 'biplane', 'birch', 'bird', 'biscuit', 'bishop', 'bison',
    'bitter', 'black', 'blade', 'blame', 'blank', 'blanket', 'blast', 'blaze',
    'blend', 'bless', 'blimp', 'blind', 'blink', 'bliss', 'blister', 'blizzard',
    'block', 'blond', 'blood', 'bloom', 'blossom', 'blouse', 'blow', 'blue',
    'board', 'boast', 'boat', 'bobbin', 'bobby', 'body', 'boil', 'bold',
    'bolt', 'bomb', 'bond', 'bone', 'bonnet', 'bonus', 'bony', 'book',
    'boom', 'boost', 'boot', 'booth', 'border', 'boring', 'borrow', 'boss',
    'botany', 'bottle', 'bottom', 'bounce', 'bound', 'bounty', 'bovine', 'bowler',
    'boxcar', 'boxer', 'boycott', 'brain', 'brake', 'branch', 'brand', 'brass',
    'brave', 'bravo', 'brawl', 'bread', 'break', 'breast', 'breath', 'breeze',
    'brick', 'bride', 'bridge', 'brief', 'bright', 'brill', 'brim', 'brine',
    'bring', 'brisk', 'broad', 'broken', 'bronze', 'brook', 'broom', 'brother',
    'brown', 'browse', 'bruise', 'brush', 'bubble', 'bucket', 'buckle', 'buddy',
    'budget', 'buffet', 'buggy', 'build', 'bulb', 'bulge', 'bullet', 'bundle',
    'bunk', 'bunny', 'burden', 'burger', 'burn', 'burst', 'bushel', 'busy',
    'butcher', 'butter', 'button', 'buyer', 'buzzard', 'cabin', 'cable', 'cacao',
    'cache', 'cackle', 'cactus', 'cadet', 'cafe', 'cage', 'cairn', 'cake',
    'calico', 'call', 'camel', 'camera', 'camp', 'campus', 'canal', 'canary',
    'cancel', 'candle', 'candy', 'cane', 'canine', 'canker', 'cannon', 'canoe',
    'canopy', 'canvas', 'canyon', 'capital', 'captain', 'carat', 'caravan', 'carbon',
    'card', 'career', 'cargo', 'caribou', 'carmine', 'carpet', 'carrot', 'cart',
    'carve', 'cascade', 'case', 'cash', 'casing', 'casket', 'castle', 'casual',
    'catacomb', 'catalog', 'catalyst', 'catch', 'category', 'cater', 'cathedral', 'cation',
    'catnap', 'catnip', 'cattle', 'caucus', 'cauldron', 'cause', 'caution', 'cavalry',
    'cave', 'cavity', 'cavy', 'cedar', 'celery', 'cellar', 'celtic', 'cement',
    'censor', 'census', 'center', 'century', 'cereal', 'ceremony', 'chafe', 'chain',
    'chair', 'chalet', 'chalk', 'chamber', 'chamois', 'champ', 'chance', 'change',
    'channel', 'chant', 'chaos', 'chapel', 'chapter', 'character', 'charcoal', 'charge',
    'chariot', 'charity', 'charm', 'charter', 'chase', 'chasm', 'chassis', 'chatter',
    'cheap', 'cheat', 'check', 'cheddar', 'cheek', 'cheer', 'cheese', 'cheetah',
    'chef', 'chemical', 'cherish', 'cherry', 'chess', 'chest', 'chevron', 'chew',
    'chicken', 'chief', 'chiffon', 'child', 'chili', 'chill', 'chime', 'chimney',
    'chimp', 'china', 'chink', 'chino', 'chip', 'chirp', 'chisel', 'chive',
    'chivalry', 'choice', 'choir', 'choose', 'chopin', 'chord', 'chorus', 'chosen',
    'chrome', 'chubby', 'chuck', 'chuckle', 'chum', 'chunk', 'church', 'churn',
    'chute', 'cider', 'cigar', 'cinder', 'cinema', 'cinnamon', 'circle', 'circuit',
    'circular', 'circus', 'cistern', 'citadel', 'citizen', 'citric', 'citrus', 'city',
    'civic', 'civil', 'clad', 'claim', 'clam', 'clamp', 'clan', 'clank',
    'clap', 'claret', 'clarify', 'clash', 'clasp', 'class', 'classic', 'clause',
    'claw', 'clay', 'clean', 'cleanse', 'clear', 'cleat', 'cleft', 'clergyman',
    'cleric', 'clerk', 'clever', 'click', 'client', 'cliff', 'climate', 'climb',
    'clinch', 'cling', 'clinic', 'clink', 'clip', 'cloak', 'clock', 'clod',
    'clog', 'cloister', 'close', 'closet', 'cloth', 'cloud', 'clout', 'clove',
    'clover', 'clown', 'club', 'cluck', 'clue', 'clump', 'clumsy', 'clutch',
    'coach', 'coal', 'coast', 'coat', 'cobalt', 'cobble', 'cobra', 'cobweb',
    'cocoon', 'codger', 'coffer', 'coffin', 'cogent', 'cognac', 'cohabit', 'cohere',
    'cohort', 'coif', 'coil', 'coin', 'coke', 'cold', 'colic', 'collar',
    'collie', 'colloquy', 'colony', 'color', 'colossus', 'colt', 'column', 'combat',
  ];

  /// Generates a random passphrase.
  ///
  /// ## Parameters
  ///
  /// - [wordCount]: Number of words in the passphrase. Default is 4.
  /// - [separator]: String used to separate words. Default is '-'.
  /// - [customWordList]: Optional custom word list. If omitted, [defaultWordList] is used.
  ///
  /// Throws [ArgumentError] if [wordCount] < 2 or the wordlist is empty.
  static String generate({
    int wordCount = 4,
    String separator = '-',
    List<String>? customWordList,
  }) {
    if (wordCount < 2) {
      throw ArgumentError('wordCount must be at least 2.');
    }

    final words = customWordList ?? defaultWordList;
    if (words.isEmpty) {
      throw ArgumentError('Word list must not be empty.');
    }

    final selected = List<String>.generate(
      wordCount,
      (_) => words[SecureRandom.nextInt(words.length)],
    );

    return selected.join(separator);
  }

  /// Calculates the entropy (in bits) of a passphrase configuration.
  ///
  /// Entropy formula: `wordCount * log2(wordListSize)`.
  ///
  /// For the default 512-word list, this is exactly `wordCount * 9` bits.
  static double calculateEntropy({
    required int wordCount,
    List<String>? customWordList,
  }) {
    if (wordCount <= 0) return 0.0;
    final listSize = (customWordList ?? defaultWordList).length;
    if (listSize <= 1) return 0.0;
    return wordCount * (log(listSize) / ln2);
  }
}
